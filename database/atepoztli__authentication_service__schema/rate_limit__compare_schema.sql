create function base_database.atepoztli__authentication_service__schema.rate_limit__compare_schema(definition json, obj json) returns boolean
    language plpgsql
as
$$
DECLARE
    fields_1 TEXT[];
    field_element
             TEXT;
    result_1
             BOOLEAN := true;
BEGIN
    SELECT ARRAY(
                   SELECT(
                             JSON_ARRAY_ELEMENTS_TEXT(
                                     definition -> 'fields'
                             )
                             )
           )
    INTO fields_1;

    FOREACH field_element IN ARRAY fields_1
        LOOP
            result_1 := (obj -> field_element IS NOT NULL) AND result_1;
        END LOOP;

    RETURN result_1;

END;
$$;

alter function base_database.atepoztli__authentication_service__schema.rate_limit__compare_schema(json, json) owner to postgres;

