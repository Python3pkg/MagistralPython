'''
Created on 10 Aug 2016
@author: rizarse
'''

class PermMeta():
    
    def __init__(self, topic, perms):
        assert topic is not None, 'Topic name required'
        assert isinstance(topic, str), 'Topic name must be type of str'
        
        self._topic = topic
        self._perms = perms
        
    def topic(self):
        return self._topic
    
    def channels(self):
        return list(self._perms.keys())
    
    def readable(self, channel):
        if (self._perms == None or (channel in self._perms) == False): 
            return False
        else:
            return self._perms[channel][0]
    
    def writable(self, channel):
        if (self._perms == None or (channel in self._perms) == False): 
            return False
        else:
            return self._perms[channel][1]