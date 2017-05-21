'''
Created on 11 Aug 2016
@author: rizarse
'''

import logging
import threading

from os.path import expanduser

from kafka.consumer.group import KafkaConsumer
from magistral.client.Configs import Configs
from magistral.client.MagistralException import MagistralException
from kafka.structs import TopicPartition
from magistral.Message import Message

class GroupConsumer(threading.Thread):
        
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)
     
    def __init__(self, threadId, name, sKey, bootstrapServers, groupId, permissions, token, cipher = None, uid = None):
        threading.Thread.__init__(self)
        self.threadId = threadId
        self.name = name
        
        self.group = groupId;
        self.subKey = sKey;
        
        self.cipher = None if cipher is None else cipher;
                
        configs = Configs.consumerConfigs();
        configs["bootstrap_servers"] = bootstrapServers.split(',');
        configs["group_id"] = groupId;
        configs['enable_auto_commit'] = False;
        
        self.__isAlive = True
        
        home = expanduser("~")
        
        if uid == None:
            self.__consumer = KafkaConsumer(
                bootstrap_servers = configs["bootstrap_servers"],
                check_crcs = False,
                exclude_internal_topics = True,
                session_timeout_ms = 10000,
                reconnect_backoff_ms = 10000,
                heartbeat_interval_ms = 2000,
                retry_backoff_ms = 500,
                fetch_min_bytes = 64,
                fetch_max_wait_ms = 96,           
                enable_auto_commit = False,
                max_in_flight_requests_per_connection = 4,
                api_version = (0, 10),            
                group_id = groupId);
        else:
            self.__consumer = KafkaConsumer(
                bootstrap_servers = configs["bootstrap_servers"],
                check_crcs = False,
                exclude_internal_topics = True,
                session_timeout_ms = 10000,
                reconnect_backoff_ms = 10000,
                heartbeat_interval_ms = 2000,
                retry_backoff_ms = 500,
                fetch_min_bytes = 64,
                fetch_max_wait_ms = 96,           
                enable_auto_commit = False,
                max_in_flight_requests_per_connection = 4,
                security_protocol = 'SSL',
                ssl_check_hostname = False,
                ssl_keyfile = home + '/magistral/' + token + '/key.pem',
                ssl_cafile = home + '/magistral/' + token + '/ca.pem',
                ssl_certfile = home + '/magistral/' + token + '/certificate.pem',
                api_version = (0, 10),
                group_id = groupId);
        
        self.permissions = permissions;
        self.map = {}
        
        self.__offsets = {}
        
        
    def recordsTotally(self, data):
        size = 0;
        for val in list(data.values()): 
            if len(val) > 0: size = size + len(val);
                               
        return size;
    
    def consumerRecord2Message(self, record):                    
        payload = record[6]
                                        
        if self.cipher is not None:
            try:
                payload = self.cipher.decrypt(payload)
            except:
                pass
                                        
        msg = Message(record[0][41:], record[1], payload, record[2], record[3])
        return msg

    def run(self):
        
        threadLock.acquire(False)
        
        while self.__isAlive:
            try:

                data = self.__consumer.poll(512);
                for values in list(data.values()):
                                         
                    for value in values:
                        msg = self.consumerRecord2Message(value);
                        listener = self.map[value[0]][msg.channel()];
                        if listener is not None: listener(msg);
                        
                if len(list(data.values())) > 0: self.__consumer.commit_async(); 
                    
            except:
                pass
              
        threadLock.release()

#   ////////////////////////////////////////////////////////////////////////////////////    

    def subscribe(self, topic, channel = -1, listener = None, callback = None):
        
        assert channel is not None and isinstance(channel, int), "Channel expected as int argument"        
        if (channel < -1): channel = -1;
                
        etopic = self.subKey + "." + topic;
                           
        self.logger.debug("Subscribe -> %s : %s | key = %s", topic, channel, self.subKey);
        
        if (self.permissions == None or len(self.permissions) == 0): 
            raise MagistralException("User has no permissions for topic [" + topic + "].");
        
        self.fch = [];
        
        for meta in self.permissions:             
            if (meta.topic() != topic): continue;  
            
            if channel == -1:
                self.fch = meta.channels();
            elif channel in meta.channels():                          
                self.fch = [ channel ];  
        
        if (len(self.fch) == 0): 
            npgex = "No permissions for topic [" + topic + "] granted";
            self.logger.error(npgex);                                
            raise MagistralException(npgex);
        
        if (self.map == None or etopic not in self.map): 
            self.map[etopic] = {}
        
#         // Assign Topic-partition pairs to listen
        
        tpas = [];
        for ch in self.fch:            
            tpas.append(TopicPartition(etopic, ch));
            if (listener is not None): self.map[etopic][ch] = listener
            
            ca = self.__consumer.assignment()
            if (ca is not None):
                for tp in ca: tpas.append(tp)
        
        self.__consumer.assign(tpas);       
                
        if callback is not None: 
            callback(self.__consumer.assignment());
            
        return self.__consumer.assignment();
        
        
    def unsubscribe(self, topic):
        self.consumer.assign([]);
        self.map.remove(topic);        

    def close(self):
        self.__isAlive = False
        self.__consumer.pause()
        self.__consumer.close()
        
    logging.getLogger('kafka.conn').setLevel(logging.FATAL)
    logging.getLogger('kafka.cluster').setLevel(logging.FATAL)
    logging.getLogger('kafka.consumer.group').setLevel(logging.INFO)    
    logging.getLogger('kafka.consumer.fetcher').setLevel(logging.INFO)
    logging.getLogger('kafka.coordinator.consumer').setLevel(logging.INFO)
    logging.getLogger('kafka.producer.record_accumulator').setLevel(logging.INFO)
    
threadLock = threading.Lock()    