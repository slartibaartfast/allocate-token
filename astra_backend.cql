/* script to create a backend for the tribe app using Astra */
/* https://astra.datastax.com/

/* create a role for app users that has less authority - done manually */
/* instructions for creating a role are in the readme                  */

/* keyspaces also need to be created manually                                 */
/* see https://docs.astra.datastax.com/docs/managing-keyspaces                */
/* CREATE KEYSPACE IF NOT EXISTS app_manager                                  */
/*    WITH replication = {'class': 'NetworkTopologyStrategy', 'caas-dc': '1'} */
/*    AND durable_writes = true;

/* CREATE KEYSPACE IF NOT EXISTS tribe                                        */
/*    WITH replication = {'class': 'NetworkTopologyStrategy', 'caas-dc': '1'} */
/*    AND durable_writes = true;                                              */


USE app_manager;

/* Keep track of users and which apps they subscribe to */
CREATE TABLE IF NOT EXISTS app_user_credentials (
    email text,
    app_id uuid,
    user_id uuid,
    password text,
    app_token text,
    app_request_id uuid,
    date_creds_generated timestamp,
    PRIMARY KEY ((email, app_id, password))
);

/* Keep track of the apps in separate keyspaces  */
CREATE TABLE IF NOT EXISTS keyspace_apps (
    app_id uuid PRIMARY KEY,
    app_name text,
    keyspace_name text,
    date_created timestamp
);


/* TODO: add a table for sharing waypoints */
USE tribe;

/* A user defined datatype to store latitude and longitude coordinates */
CREATE TYPE IF NOT EXISTS tribe_geo_point_udt (
    latitude double,
    longitude double
);


CREATE TABLE IF NOT EXISTS tribe_users (
    user_id uuid PRIMARY KEY,
    user_name text,
    email text,
    date_created timestamp,
    last_login timestamp
);

/* store the last known location of a user */
/* TODO: make a partition key for user and month                        */
/* TODO: cluster ascending...WITH CLUSTERING ORDER BY (created_at ASC); */
CREATE TABLE IF NOT EXISTS tribe_user_location (
    user_id uuid,
    created_at timestamp,
    location tribe_geo_point_udt,
    PRIMARY KEY (user_id)
);

/* associate the creator of a tribe with members of that tribe */
/* owner_id and member_id are both user_id values */
CREATE TABLE IF NOT EXISTS tribe_members (
    owner_id uuid,
    member_ids set<uuid>,
    PRIMARY KEY (owner_id)
);

/* a table for messaging between users */
/* sender_id and receiver_id are both existing user_id values */
CREATE TABLE IF NOT EXISTS tribe_messages (
    message_id uuid,
    sender_id uuid,
    receiver_id uuid,
    body text,
    PRIMARY KEY ((message_id, sender_id))
);
