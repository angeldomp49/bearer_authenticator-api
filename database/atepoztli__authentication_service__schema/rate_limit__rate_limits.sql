create table base_database.atepoztli__authentication_service__schema.rate_limit__rate_limits
(
    id            bigserial
        constraint rate_limit__rate_limits_pk
            primary key,
    title         varchar(100)     not null
        constraint rate_limit__rate_limits_pk_2
            unique,
    attempts      bigint default 0 not null,
    unit          varchar(255)     not null,
    time_quantity bigint default 0 not null,
    schema        json   default '{
      "fields": []
    }'                             not null
);

