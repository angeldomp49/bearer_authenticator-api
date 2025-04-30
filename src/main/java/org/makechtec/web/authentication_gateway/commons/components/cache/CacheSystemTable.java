package org.makechtec.web.authentication_gateway.commons.components.cache;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class CacheSystemTable {

    private final Map<String, String> cachedEntries = new HashMap<>();
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();

    private final Map<String, FillCacheCallback> callbacks = new HashMap<>();
    private final ReentrantReadWriteLock callbackLock = new ReentrantReadWriteLock();

    public String request(String key) {
        if (!this.contains(key)) {
            var callback = this.getCallback(key);
            this.put(key, callback.fill());
        }

        return this.get(key);
    }

    public void flushAll() {
        try {
            lock.writeLock().lock();
            cachedEntries.clear();
        } finally {
            lock.writeLock().unlock();
        }
    }

    public void flushSpecific(String key) {
        try {
            lock.writeLock().lock();
            cachedEntries.remove(key);
        } finally {
            lock.writeLock().unlock();
        }
    }

    public void put(String key, String value) {
        try {
            lock.writeLock().lock();
            cachedEntries.put(key, value);
        } finally {
            lock.writeLock().unlock();
        }
    }

    public boolean nonContains(String key) {
        return !this.contains(key);
    }

    public boolean contains(String key) {
        try {
            lock.readLock().lock();
            return cachedEntries.containsKey(key);
        } finally {
            lock.readLock().unlock();
        }
    }

    public String get(String key) {
        try {
            lock.readLock().lock();
            return cachedEntries.get(key);
        } finally {
            lock.readLock().unlock();
        }
    }

    public FillCacheCallback getCallback(String key) {
        try {
            callbackLock.readLock().lock();
            return callbacks.get(key);
        } finally {
            callbackLock.readLock().unlock();
        }
    }

    public void putCallback(String key, FillCacheCallback callback) {
        try {
            callbackLock.writeLock().lock();
            callbacks.put(key, callback);
        } finally {
            callbackLock.writeLock().unlock();
        }
    }

}
