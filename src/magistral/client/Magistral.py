'''
Created on 9 Aug 2016
@author: rizarse
'''

import re
import sys
import time
import logging
import paho.mqtt.client as mqtt

from magistral.client.IAccessControl import IAccessControl
from magistral.client.IMagistral import IMagistral
from magistral.client.util.RestApiManager import RestApiManager
from magistral.client.util.JsonConverter import JsonConverter
from magistral.client.sub.GroupConsumer import GroupConsumer
from magistral.client.sub.SubMeta import SubMeta
from magistral.client.topics.TopicMeta import TopicMeta
from magistral.client.MagistralException import MagistralException

from kafka.producer.kafka import KafkaProducer
from kafka.producer.future import RecordMetadata
from magistral.client.pub.PubMeta import PubMeta
from magistral.client.IHistory import IHistory

from magistral.client.sub.MagistralConsumer import MagistralConsumer

class Magistral(IMagistral, IAccessControl, IHistory):

    logger = logging.getLogger(__name__);
    
    __host = "app.magistral.io"
    __mqtt = None;
    
    __consumerMap = {}
    __producerMap = {}
    __permissions = None
    
    def __init__(self, pubKey, subKey, secretKey, ssl = False, cipher = None):
        
        assert pubKey is not None and subKey is not None and secretKey is not None, 'Publish, Subscribe and Secret key must be specified' 
        
        pk_regex = re.compile('^pub-[a-f0-9]{8}-?[a-f0-9]{4}-?4[a-f0-9]{3}-?[89ab][a-f0-9]{3}-?[a-f0-9]{12}\Z', re.I)
        sk_regex = re.compile('^sub-[a-f0-9]{8}-?[a-f0-9]{4}-?4[a-f0-9]{3}-?[89ab][a-f0-9]{3}-?[a-f0-9]{12}\Z', re.I)
        ak_regex = re.compile('^s-[a-f0-9]{8}-?[a-f0-9]{4}-?4[a-f0-9]{3}-?[89ab][a-f0-9]{3}-?[a-f0-9]{12}\Z', re.I)
        
        assert pk_regex.match(pubKey), 'Invalid format of publish key'
        assert sk_regex.match(subKey), 'Invalid format of subscribe key'
        assert ak_regex.match(secretKey), 'Invalid format of secret key'
                
        self.pubKey = pubKey;
        self.subKey = subKey;
        self.secretKey = secretKey;
        
        self.cipher = cipher;
        self.ssl = False;
               
        self.__connectionSettings()
        
        def permCallback(perms):
            if (perms != None):
                if self.__permissions is None: self.__permissions = []
                self.__permissions.extend(perms)
            
        self.permissions(None, lambda perms : permCallback(perms));
        
    def setHost(self, host):
        assert host is not None, 'Host name required'
        self.__host = host;
        
    def __connectionSettings(self):
        
        url = "https://" + self.__host + "/api/magistral/net/connectionPoints";
        user = self.pubKey + "|" + self.subKey;
#         
        def conPointsCallback(json, err):
            if (err != None):
                self.logger.error(err)
                return
            else:            
                self.logger.debug("Received Connection Points : %s", json);                
                self.settings = JsonConverter.connectionSettings(json);
                                
                for setting in (self.settings["pub"]["ssl"] if self.ssl else self.settings["pub"]["plain"]):        
                    p = KafkaProducer(bootstrap_servers = setting["bootstrap_servers"], partitioner = None);  
                    
                    self.token = self.settings["meta"]["token"]
                    for key, val in setting.iteritems():
                        p.config[key] = val;
                    
                    p.config['client_id'] = self.token;          
                                                 
                    self.__producerMap[self.token] = p;                    
                    break;
                
                                               
                self.__initMqtt(self.token);
#         
        return RestApiManager.get(url, None, user, self.secretKey, lambda json, err: conPointsCallback(json, err));     
    
    def __initMqtt(self, token):
        self.logger.debug("Init MQTT with token : [%s]", token);
        
        clientId = "magistral.mqtt.gw." + token;
        username = self.pubKey + "|" + self.subKey;
        
        def conCallback(client, userdata, flags, rc):
            self.__mqtt.publish("presence/" + self.pubKey + "/" + token, payload=bytes([0]), qos=1, retain=True);
        
        def messageReceivedCallback():
            pass
                
        self.__mqtt = mqtt.Client(clientId, True, None, mqtt.MQTTv311, transport="tls");        
        self.__mqtt.username_pw_set(username, self.secretKey);
        self.__mqtt.will_set(topic = "presence/" + self.pubKey + "/" + token, payload=bytes([0]), qos=1, retain=True);
        
        self.__mqtt.on_connect = conCallback
        
        self.logger.debug("Connect to MQTT with token : [%s:%d]", self.__host, 1883);        
        self.__mqtt.connect(self.__host, port=1883, keepalive=60, bind_address="")
        

    def permissions(self, topic=None, callback=None):
        
        if self.__permissions is None:
            url = "https://" + self.__host + "/api/magistral/net/permissions"
            
            params = None;
            if (topic != None): params = { "topic" : topic }
               
            auth = self.pubKey + "|" + self.subKey;   
            
            json = RestApiManager.get(url, params, auth, self.secretKey); # , lambda json, err: permsRestCallback(json, err)
            perms = JsonConverter.userPermissions(json);
            
            self.__permissions = perms;
           
            if (callback is not None): callback(self.__permissions);        
            return self.__permissions;
        else:
            if topic is None:
                if (callback is not None): callback(self.__permissions);        
                return self.__permissions;
            else:                
                for perm in self.__permissions:
                    if perm.topic() != topic : continue
                    
                    if (callback is not None): callback([perm]);        
                    return [perm];
                 
                if (callback is not None): callback(None);        
                return None;   
                    
                    

    def grant(self, user, topic, read, write, ttl=0, channel=-1, callback=None):
        
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
                    
                    c = GroupConsumer(self.subKey, bs, group, self.__permissions, self.cipher);
                    self.__consumerMap[group][bs] = c;
            
            for bs, gc in self.__consumerMap[group].iteritems():
                
                def asgCallback(assignment):
                    
                    for asgm in assignment:
                        if (asgm[0] != self.subKey + "." + topic): continue;
                        try:
                            meta = SubMeta(group, topic, [channel], bs);
                            if (callback != None): callback(meta);
#                             return meta;
                        except:
                            self.logger.error("ERROR = %s", sys.exc_info()[1]);
                        break;
                
                meta = gc.subscribe(topic, channel, listener, lambda assignment : asgCallback(assignment));
                gc.start();
                
                return meta;
                 
        except:
            pass

    def unsubscribe(self, topic, channel=-1, callback=None):        
        for groupName, consmap in self.__consumerMap.iteritems():
            for conString, gc in consmap.iteritems():
                gc.unsubscribe(self.subKey + "." + topic);
                
                meta = SubMeta(groupName, topic, channel, conString);
                if (callback != None): callback(meta)
                return meta;
    
    def __recordMetadata2PubMeta(self, meta):
        assert isinstance(meta, RecordMetadata);
        return PubMeta(meta[0], int(meta[1]), meta[4])

    def publish(self, topic, msg, channel=-1, callback=None):
        
        assert(topic is not None)
        assert(msg is not None)       
        
        try:            
            if topic == None:
                raise MagistralException("Topic name must be specified");
            
            topicMeta = self.topic(topic);
             
            if topicMeta == None:
                raise MagistralException("Topic " + topic + " cannot be found");
            
            if channel == None or channel < -1:
                channel = -1;
            
            chs = topicMeta.channels();
            if (channel >= len(chs)):
                raise MagistralException("There is no channel [" + channel + "] for topic " + topic);
            
            if self.__producerMap == None or len(self.__producerMap) == 0:
                raise MagistralException("Unable to publish message -> Client is not connected to the Service");
            
            token = self.__producerMap.keys()[0];
            p = self.__producerMap[token];
            
            realTopic = self.pubKey + "." + topic;     
            
            key = bytes(self.secretKey + "-" + token);
            
            if channel == -1:
                for ch in chs:
                    p.send(topic = realTopic, value = bytes(msg), key = key, partition = int(ch));
            else: 
                future = p.send(topic = realTopic, value = bytes(msg), key = key, partition = int(channel)).add_callback(lambda ack : pubCallback(ack));
                        
                def pubCallback(ack):                    
                    if callback is not None: 
                        callback(self.__recordMetadata2PubMeta(ack))
                    
                ack = future.get(5);
                return self.__recordMetadata2PubMeta(ack);
            
        except:
            self.logger.error("Error [%s] : %s", sys.exc_info()[0], sys.exc_info()[1])            
            raise MagistralException(sys.exc_info()[1]);

    def topics(self, callback=None):
            
        perms = self.permissions();
        
        metaList = [];            
        for pm in perms: 
            metaList.append(TopicMeta(pm.topic, pm.channels()));
            
        if callback != None: callback(metaList, None);            
        return metaList;
     

    def topic(self, topic, callback = None):
        
        assert topic is not None, 'Topic name required'
        
        perms = self.permissions(topic);
                    
        metaList = None;            
        for pm in perms: 
            metaList = TopicMeta(pm.topic, pm.channels());
            
        if callback is not None: callback(metaList);                      
        return metaList;
                
    def history(self, topic, channel, count, start = 0, callback=None):
        
        assert topic is not None, 'Topic name required'
        assert channel is not None and isinstance(channel, int), 'Channel number required as int parameter'
        
        assert count is not None, 'Number of records to return must be positive'
        
        bs = self.settings['sub']['plain'][0]['bootstrap_servers'];
        
        mc = MagistralConsumer(self.pubKey, self.subKey, self.secretKey, bs, None);
        
        res = []
        if start > 0:
            res.extend(mc.history(topic, channel, count));
        else:
            res.extend(mc.historyForTimePeriod(topic, channel, start, end = int(round(time.time() * 1000)), limit = count));
            
        if callback is not None: callable(res);
        return res;        
            
    def historyIn(self, topic, channel, start=0, end=int(round(time.time() * 1000)), callback=None):
        
        assert topic is not None, 'Topic name required'
        assert channel is not None and isinstance(channel, int), 'Channel number required as int parameter'
        
        bs = self.settings['sub']['plain'][0]['bootstrap_servers'];
        
        mc = MagistralConsumer(self.pubKey, self.subKey, self.secretKey, bs, None);
        res = mc.historyForTimePeriod(topic, channel, start, end)
        
        if res is not None:
            if callback is not None: callable(res);
        else: 
            return None;

    def close(self):        
        for bsmap in self.__consumerMap.values():
            for c in bsmap.values(): c.close;  
                  
        self.__mqtt.disconnect();        
        