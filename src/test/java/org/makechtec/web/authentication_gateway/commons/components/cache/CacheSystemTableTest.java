package org.makechtec.web.authentication_gateway.commons.components.cache;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

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

    @Test
    void fillCallback() {
        final var table = new CacheSystemTable();

        table.putCallback("key1", () -> "value1");

        final var result = table.request("key1");

        assertEquals("value1", result);

        table.put("key2", "value2");

        final var result2 = table.request("key2");

        assertEquals("value2", result2);
    }

    @Test
    void nonContains() {
        final var table = new CacheSystemTable();

        table.put("key1", "value1");

        assertFalse(table.nonContains("key1"));
        assertTrue(table.nonContains("key2"));
    }

}