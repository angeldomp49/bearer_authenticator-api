package org.makechtec.web.authentication_gateway.commons.components.cache;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class CacheSystemTable {
    
    private final Map<String, String> cacheEntries = new HashMap<>();
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();
    
    public void flushAll(){
        try {
            lock.writeLock().lock();
            cacheEntries.clear();
        }finally {
            lock.writeLock().unlock();
        }
    }
    
    public void flushSpecific(String key){
        try {
            lock.writeLock().lock();
            cacheEntries.put(key, null);
        }finally {
            lock.writeLock().unlock();
        }
    }
    
    public void put(String key, String value){
        try {
            cacheEntries.put(key, value);
        }finally {
            lock.writeLock().unlock();
        }
    }
    
    public String request(String key){
        try {
            lock.readLock().lock();
            return cacheEntries.get(key);
        }finally {
            lock.readLock().unlock();
        }
    }
    
    public boolean contains(String key){
        try {
            lock.readLock().lock();
            return cacheEntries.containsKey(key);
        }finally {
            lock.readLock().unlock();
        }
    }
    
}
