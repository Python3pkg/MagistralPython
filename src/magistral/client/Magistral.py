'''
Created on 9 Aug 2016
@author: rizarse
'''

import re
import sys
import jks
import time
import base64
import logging
import paho.mqtt.client as mqtt
from .magistral.client.util.JksHandler import JksHandler

from os.path import expanduser, os

from .magistral.client.IAccessControl import IAccessControl
from .magistral.client.IMagistral import IMagistral
from .magistral.client.util.RestApiManager import RestApiManager
from .magistral.client.util.JsonConverter import JsonConverter
from .magistral.client.sub.GroupConsumer import GroupConsumer
from .magistral.client.sub.SubMeta import SubMeta
from .magistral.client.topics.TopicMeta import TopicMeta
from .magistral.client.MagistralException import MagistralException

from kafka.producer.future import RecordMetadata
from .magistral.client.pub.PubMeta import PubMeta
from .magistral.client.IHistory import IHistory

from .magistral.client.sub.MagistralConsumer import MagistralConsumer
from .magistral.client.util.aes import AESCipher
import shutil
from .magistral.client.pub.Producer import Producer
import inspect
import collections


class Magistral(IMagistral, IAccessControl, IHistory):

    logger = logging.getLogger(__name__);
    logger.setLevel(logging.INFO)
    
    __host = "app.magistral.io"
    
    def __init__(self, pubKey, subKey, secretKey, cipher = None):
        
        assert pubKey is not None and subKey is not None and secretKey is not None, 'Publish, Subscribe and Secret key must be specified' 
        assert isinstance(pubKey, str) and isinstance(subKey, str) and isinstance(secretKey, str), 'Publish, Subscribe and Secret key must be type of str'
        
        pk_regex = re.compile('^pub-[a-f0-9]{8}-?[a-f0-9]{4}-?4[a-f0-9]{3}-?[89ab][a-f0-9]{3}-?[a-f0-9]{12}\Z', re.I)
        sk_regex = re.compile('^sub-[a-f0-9]{8}-?[a-f0-9]{4}-?4[a-f0-9]{3}-?[89ab][a-f0-9]{3}-?[a-f0-9]{12}\Z', re.I)
        ak_regex = re.compile('^s-[a-f0-9]{8}-?[a-f0-9]{4}-?4[a-f0-9]{3}-?[89ab][a-f0-9]{3}-?[a-f0-9]{12}\Z', re.I)
        
        assert pk_regex.match(pubKey), 'Invalid format of publish key'
        assert sk_regex.match(subKey), 'Invalid format of subscribe key'
        assert ak_regex.match(secretKey), 'Invalid format of secret key'
                
        self.pubKey = pubKey
        self.subKey = subKey
        self.secretKey = secretKey
        
        if cipher is not None:
            assert isinstance(cipher, str), 'Cipher expected as string'
            assert len(cipher), 'Minimal length of cipher key is 16 symbols'
            
            if len(cipher) > 16: cipher = cipher[:15]            
            self.cipher = AESCipher(cipher); 
        else:
            self.cipher = None
        
        self.ssl = True
        
        self.__consumerMap = {}
        self.__producerMap = {}
        self.__permissions = None
               
        self.__connectionSettings()            
        self.permissions();
        
    def setHost(self, host):
        """
        Sets host name of coordinating node [dedicated deployments]
        :param host: string URL of the host
        """    
        assert host is not None, 'Host name required'
        assert host is not None, 'Host name required'
        self.__host = host;
        
    
    def __doCerts(self, sts, sks, token):
        
        home = expanduser("~")
        
#         if os.path.exists(home + '/magistral') == False:
#             os.makedirs(home + '/magistral')
             
        if os.path.exists(home + '/magistral/tmp') == False:
            os.makedirs(home + '/magistral/tmp')
        
        with open(home + '/magistral/tmp/ts', 'wb') as f:
            f.seek(0)
            f.write(bytearray(base64.standard_b64decode(sts)))
            f.close()
    
        with open(home + '/magistral/tmp/ks', 'wb') as f:
            f.seek(0)
            f.write(bytearray(base64.standard_b64decode(sks)))                    
            f.close()           
                           
        ks = jks.KeyStore.load(home + '/magistral/tmp/ks', 'magistral')
            
        self.uid = JksHandler.writePkAndCerts(ks, token)
        
        if os.path.exists(home + '/magistral/tmp'): 
            shutil.rmtree(home + '/magistral/tmp')
        
    def __connectionSettings(self):
        
        url = "https://" + self.__host + "/api/magistral/net/connectionPoints";
        user = self.pubKey + "|" + self.subKey;
#         
        def conPointsCallback(json, err):
            if (err != None):
                self.logger.error(err)
                return
            else:            
                self.logger.debug("Received Connection Points : %s", json)    
                self.settings = JsonConverter.connectionSettings(json)
                
                self.token = self.settings["meta"]["token"];
                
                self.__doCerts(self.settings['ts'], self.settings['ks'], self.token)
                            
                for setting in (self.settings["pub"]["ssl"] if self.ssl else self.settings["pub"]["plain"]):
                                        
                    p = Producer(setting, self.uid, self.token)       
                                                 
                    self.__producerMap[self.token] = p;       
                    p.start();             
                    break;
                                               
                self.__initMqtt(self.token);
#         
        return RestApiManager.get(url, None, user, self.secretKey, lambda json, err: conPointsCallback(json, err));     
    
    def __initMqtt(self, token):
        
        self.logger.debug("Init MQTT with token : [%s]", token);
        
        clientId = "magistral.mqtt.gw." + token;
        username = self.pubKey + "|" + self.subKey;
        
        def conCallback(client, userdata, flags, rc):
            self.__mqtt.publish("presence/" + self.pubKey + "/" + token, payload=bytearray([0]), qos=1, retain=True);
        
        def messageReceivedCallback():
            pass
                
        self.__mqtt = mqtt.Client(clientId, True, None, mqtt.MQTTv311, transport="tls");        
        self.__mqtt.username_pw_set(username, self.secretKey);
        self.__mqtt.will_set(topic = "presence/" + self.pubKey + "/" + token, payload=bytearray([0]), qos=1, retain=True);
        
        self.__mqtt.on_connect = conCallback
        
        self.logger.debug("Connect to MQTT with token : [%s:%d]", self.__host, 1883);        
        self.__mqtt.connect(self.__host, port=1883, keepalive=60, bind_address="")
        

    def permissions(self, topic=None, callback=None):
        
        """ Retrieves user permissions

        :param topic: (optional) Topic name to get permissions for
        :param callback: (optional) callback with permissions -> array of :class:`PermMeta`.
        
        :return: :class: array of :class:`PermMeta`
        """
        
        if self.__permissions is None:
            url = "https://" + self.__host + "/api/magistral/net/permissions"
            
            params = None;
            if (topic != None): params = { "topic" : topic }
               
            auth = self.pubKey + "|" + self.subKey;   
            
            json = RestApiManager.get(url, params, auth, self.secretKey); # , lambda json, err: permsRestCallback(json, err)
            perms = JsonConverter.userPermissions(json);
            
            self.__permissions = [];
            self.__permissions.extend(perms);
           
            if (callback is not None): callback(self.__permissions);        
            return self.__permissions;
        else:
            if topic is None:
                if (callback is not None): callback(self.__permissions);        
                return self.__permissions;
            else:                
                permissions = [];
                
                for perm in self.__permissions:
                    if perm.topic() != topic : continue                    
                    permissions.extend([perm]);
                 
                if (callback is not None): callback(permissions);        
                return permissions;
            

    def grant(self, user, topic, read, write, ttl=0, channel=-1, callback=None):
        
        """ Grants permanent or temporary permissions to access network resources
        
        :param user: (str) user name
        :param topic: (str) topic name
        :param read: (bool) permission to read from channel(s)
        :param write: (bool) permission to write to channel(s)
        
        :param ttl: (int) (optional) Time-to-Live for permission [0 - is permanent, > 0 - are temporary]
        :param channel: (int) (optional) Number of channel permission should be granted for [ -1 - to all in the topic, >=0 - number of specific channel]
       
        :param callback: (optional) callback with up-to-date permissions -> array of :class:`PermMeta`.
        
        :return: :class: array of :class:`PermMeta`
        """
        
        assert user is not None, 'User name is required'
        assert topic is not None, 'Topic is required'
        
        assert isinstance(read, bool) and isinstance(write, bool), 'read/write permissions must be type of bool'
        
        url = "https://" + self.__host + "/api/magistral/net/grant"
        params = { 'user': user, 'topic': topic, 'read': read, 'write': write }
        
        if (channel > -1): 
            params['channel'] = channel;
        
        if (ttl > 0):
            params["ttl"] = ttl;
       
        auth = self.pubKey + "|" + self.subKey;
        
        def updatedUserPermsCallback(_userPerms, err):
            perms = JsonConverter.userPermissions(_userPerms);
            if (callback != None): callback(perms, err);
            return perms;
        
        def grantRestCallback(json, err) :
            if (callback != None and err == None) : 
                url = "https://" + self.__host + "/api/magistral/net/user_permissions"
                RestApiManager.get(url, {"userName" : user}, auth, self.secretKey, lambda userPerms, err: updatedUserPermsCallback(userPerms, err))   
        
        RestApiManager.put(url, params, auth, self.secretKey, lambda json, err: grantRestCallback(json, err));


    def revoke(self, user, topic, channel=-1, callback=None):
        
        """ Revokes user permission
        
        :param user: (str) user name
        :param topic: (str) topic name

        :param channel: (int) (optional) Number of channel for revocation [ -1 - from all in the topic, >=0 - number of specific channel]
       
        :param callback: (optional) callback with up-to-date permissions -> array of :class:`PermMeta`.
        
        :return: :class: array of :class:`PermMeta`
        """
        
        assert user is not None, 'User name is required'
        assert topic is not None, 'Topic is required'
                
        url = "https://" + self.__host + "/api/magistral/net/revoke"
        params = { 'user': user, 'topic': topic }
        
        if (channel > -1): 
            params['channel'] = channel;
               
        auth = self.pubKey + "|" + self.subKey;
        
        def updatedUserPermsCallback(_userPerms, err):
            perms = JsonConverter.userPermissions(_userPerms);
            if (callback != None): callback(perms, err);
            return perms;
        
        def delRestCallback(json, err) :
            if (callback != None and err == None) : 
                url = "https://" + self.__host + "/api/magistral/net/user_permissions"
                RestApiManager.get(url, {"userName" : user}, auth, self.secretKey, lambda userPerms, err: updatedUserPermsCallback(userPerms, err))   
        
        RestApiManager.delete(url, params, auth, self.secretKey, lambda json, err: delRestCallback(json, err));


    def subscribe(self, topic, group="default", channel=-1, listener=None, callback=None):
        
        """ Subscribes to topic / channel
        
        :param topic: (str) topic name
        :param group: (str) group name
        
        :param channel: (int) (optional) Number of channel to subscribe [ -1 - to all in the topic, >=0 - number of specific channel]
       
        :param callback: (optional) callback with subscription ack -> :class:`SubMeta`.
        
        :return: :class: `SubMeta`
        """
        
        assert isinstance(topic, str), 'Topic must be type of str'
        assert isinstance(channel, int), 'Channel must be type of int'
        
        try :
            if group == None: group = "default"; 
            
            if group not in self.__consumerMap:
                self.__consumerMap[group] = {}
            
            cm = self.__consumerMap[group];

            consumersCount = 0;
            if self.ssl:
                consumersCount = len(self.settings["sub"]["ssl"]) if "ssl" in self.settings["sub"] else 0; 
            else :
                consumersCount = len(self.settings["sub"]["plain"]) if "plain" in self.settings["sub"] else 0;

            if len(cm) < consumersCount: # No enough consumers are there
                
                # TODO CIPHER
                
                for setting in (self.settings["sub"]["ssl"] if self.ssl else self.settings["sub"]["plain"]):
                    
                    bs = setting["bootstrap_servers"]
                    if (bs in cm): continue;
                         
                    threadId = 'thread_id_consumer_' + group
                    name = 'thread_name_consumer_' + group
                    
                    c = GroupConsumer(threadId, name, self.subKey, bs, group, self.__permissions, self.token, self.cipher, self.uid);
                    self.__consumerMap[group][bs] = c;
            
            for bs, gc in list(self.__consumerMap[group].items()):
                
                def asgCallback(assignment, triggerCallbacks = False):
                    
                    meta = None;
                    
                    for asgm in assignment:
                        if (asgm[0] != self.subKey + "." + topic): continue;
                        
                        try:
                            meta = SubMeta(group, topic, asgm[1], bs);
                            if (triggerCallbacks == True and callback != None): callback(meta, None);
                            return meta;
                        except:
                            self.logger.error("ERROR = %s", sys.exc_info()[1]);
                            if (triggerCallbacks == True and callback != None): callback(None, sys.exc_info()[1]);
                            return None;
                        break;
                
                asgn = gc.subscribe(topic, channel, listener, lambda assignment : asgCallback(assignment, True))
                gc.start();
                
                res = asgCallback(asgn, False)                
                return res;
                 
        except:
            pass

    def unsubscribe(self, topic, channel=-1, callback=None): 
        
        """ Unsubscribes from topic / channel
        
        :param topic: (str) topic name
        
        :param channel: (int) (optional) Number of channel to unsubscribe from [ -1 - to all in the topic, >=0 - number of specific channel]
       
        :param callback: (optional) callback with unsubscription ack -> :class:`SubMeta`.
        
        :return: :class: `SubMeta`
        """
               
        for groupName, consmap in list(self.__consumerMap.items()):
            for conString, gc in list(consmap.items()):
                gc.unsubscribe(self.subKey + "." + topic);
                
                meta = SubMeta(groupName, topic, channel, conString);
                if (callback != None): callback(meta)
                return meta;
    
    def __recordMetadata2PubMeta(self, meta):
        assert isinstance(meta, RecordMetadata);
        return PubMeta(meta[0], int(meta[1]), meta[4])

    def publish(self, topic, msg, channel=-1, callback=None):
        
        """ Send messages to topic / channel(s)
        
        :param topic: (str) topic name
        :param msg: (bytes) message content
        
        :param channel: (int) (optional) Number of channel to send message to [ -1 - to all in the topic, >=0 - number of specific channel]
       
        :param callback: (optional) callback with publish ack -> :class:`PubMeta`.
        
        :return: :class: `PubMeta`
        """
        
        assert(topic is not None), 'Topic is required'
        assert(msg is not None and isinstance(msg, bytes)), 'Message body is required an an non-empty bytearray'
        
        if self.cipher is not None: # encrypt
            msg = self.cipher.encrypt(msg); # AES/ECB + Base64 encrypted string 
        
        try:            
            if topic == None:
                raise MagistralException("Topic name must be specified");
            
            topicMeta = self.topic(topic);
             
            if topicMeta == None:
                raise MagistralException("Topic " + topic + " cannot be found");
            
            if channel == None or channel < -1:
                channel = -1;
            
            chs = topicMeta.channels();
            if (channel not in chs):
                raise MagistralException("There is no channel [" + str(channel) + "] available for topic " + topic);
            
            if self.__producerMap == None or len(self.__producerMap) == 0:
                raise MagistralException("Unable to publish message -> Client is not connected to the Service");
            
            token = list(self.__producerMap.keys())[0];
            p = self.__producerMap[token];
            
            realTopic = self.pubKey + "." + topic;     
            
            key = bytes(self.secretKey + "-" + token, 'utf8')
            
            if channel == -1:
                for ch in chs:
                    p.publish(topic = realTopic, value = msg, key = key, partition = int(ch))
#                     p.send(topic = realTopic, value = msg, key = key, partition = int(ch));
            else: 
                future = p.publish(topic = realTopic, value = msg, key = key, partition = int(channel)).add_callback(lambda ack : pubCallback(ack));
#                 future = p.send(topic = realTopic, value = msg, key = key, partition = int(channel)).add_callback(lambda ack : pubCallback(ack));
                        
                def pubCallback(ack):                    
                    if callback is not None: 
                        callback(self.__recordMetadata2PubMeta(ack))
                    
                ack = future.get();
                return self.__recordMetadata2PubMeta(ack);
            
        except:
            ex = list(sys.exc_info())
            self.logger.error("Error [%s] : %s", ex[0], ex[1])            
            raise MagistralException(ex[1]);

    def topics(self, callback=None):  
        
        """ Returns information about available topics / channels for user
        
        :return: array of :class:`TopicMeta`
        """
                  
        perms = self.permissions();
        
        metaList = [];            
        for pm in perms:            
            meta = TopicMeta(pm.topic(), list(pm.channels()))            
            metaList.append(meta);
            
        if callback != None: callback(metaList);            
        return metaList;
     

    def topic(self, topic, callback = None):
        
        """ Returns information about topic available for user
        
        :param topic: (str) topic name
         
        :return: array of :class:`TopicMeta`
        """
        
        assert topic is not None, 'Topic name required'
        
        perms = self.permissions(topic);
        if perms is None: return None
        
        channels = []            
        for pm in perms:
            channels.extend(pm.channels())
        
        metaList = TopicMeta(topic, channels);
        if callback is not None: callback(metaList);                      
        return metaList;
                
    def history(self, topic, channel, count, start = -1, callback=None):
        
        """ Returns last messages sent over channel 
        
        :param topic: (str) topic name
        :param channel: (int) channel number
        :param count: (int) quantity of messages to return
        
        :param start: (optional) start point of epoch to fetch messages from
        :param callback: (optional) callback with array of :class:`Message`
         
        :return: array of :class:`Message`
        """
        
        assert topic is not None, 'Topic name required'
        assert channel is not None and isinstance(channel, int), 'Channel number required as int parameter'
        
        assert count is not None, 'Number of records to return must be positive'
        
        if self.ssl:
            bs = self.settings['sub']['ssl'][0]['bootstrap_servers'] 
        else:
            bs = self.settings['sub']['plain'][0]['bootstrap_servers']
        
        mc = MagistralConsumer(self.pubKey, self.subKey, self.secretKey, bs, self.token, None, self.uid);
        
        res = []
        if inspect.ismethod(start) == False and start < 0:
            res.extend(mc.history(topic, channel, count));
        else:
            res.extend(mc.historyForTimePeriod(topic, channel, start, end = int(round(time.time() * 1000)), limit = count));
            
        if callback is not None: callback(res);
        return res;        
            
    def historyIn(self, topic, channel, start=0, end=int(round(time.time() * 1000)), callback=None):
        
        """ Returns sent messages within time interval 
        
        :param topic: (str) topic name
        :param channel: (int) channel number
       
        :param start: (optional) start of epoch
        :param end: (optional) end of epoch

        :param callback: (optional) callback with array of :class:`Message`
         
        :return: array of :class:`Message`
        """
        
        assert topic is not None, 'Topic name required'
        assert channel is not None and isinstance(channel, int), 'Channel number required as int parameter'
        
        bs = self.settings['sub']['plain'][0]['bootstrap_servers'];
        
        mc = MagistralConsumer(self.pubKey, self.subKey, self.secretKey, bs, self.token, None, self.uid);
        res = mc.historyForTimePeriod(topic, channel, start, end)
        
        if res is not None:
            if callback is not None: isinstance(res, collections.Callable);
        else: 
            return None;

    def close(self):
        
        """
        Terminates all network activity.
        Magistral should be re-instantiated after this
        """
                
        for p in list(self.__producerMap.values()):
            p.close()
        
        for bsmap in list(self.__consumerMap.values()):
            for c in list(bsmap.values()): c.close();  
                  
        self.__mqtt.disconnect();
        
    logging.getLogger('kafka.conn').setLevel(logging.INFO)  
    logging.getLogger('kafka.client').setLevel(logging.INFO) 
    logging.getLogger('kafka.coordinator').setLevel(logging.INFO) 
    logging.getLogger('kafka.metrics.metrics').setLevel(logging.INFO) 
    logging.getLogger('kafka.producer.kafka').setLevel(logging.INFO)
    logging.getLogger('kafka.producer.sender').setLevel(logging.INFO)