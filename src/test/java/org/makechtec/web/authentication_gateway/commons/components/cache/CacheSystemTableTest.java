package org.makechtec.web.authentication_gateway.commons.components.cache;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CacheSystemTableTest {

    @Test
    void flushAll() {
        var table = new CacheSystemTable();

        table.put("key1", "value1");
        table.put("key2", "value2");

        table.flushAll();

        assertFalse(table.contains("key1"));

    }

    @Test
    void flushSpecific() {
        var table = new CacheSystemTable();

        table.put("key1", "value1");
        table.put("key2", "value2");

        table.flushSpecific("key1");

        assertFalse(table.contains("key1"));
        assertTrue(table.contains("key2"));

    }

}