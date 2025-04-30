create table base_database.atepoztli__authentication_service__schema.rate_limit__client_attempts
(
    id         bigserial
        constraint rate_limit__client_attempts_pk
            primary key,
    obj        json      default '{}'  not null,
    title      varchar(100)            not null,
    created_at timestamp default NOW() not null
);

