/* load some sample data for testing */

BEGIN BATCH
INSERT INTO tribe_users (user_id, user_name, email, date_created, last_login)
  VALUES(00000000-0000-0000-0000-000000000000, 'MrDogDogalina',
  'dogdogalina@mrdogdogalina.com', toTimestamp(now()), toTimestamp(now()))
INSERT INTO tribe_user_credentials (email, password, user_id)
  VALUES ('dogdogalina@mrdogdogalina.com', 'ff9k3l2',
  00000000-0000-0000-0000-000000000000)
APPLY BATCH;

BEGINE BATCH
INSERT INTO tribe_users (user_id, user_name, email, date_created, last_login)
  VALUES(11111111-1111-1111-1111-111111111111, 'User1', 'user1@jive.org',
  toTimestamp(now()), toTimestamp(now()))
INSERT INTO tribe_user_credentials (email, password, user_id)
  VALUES ('user1@jive.org', 'password1',
  11111111-1111-1111-1111-111111111111)
APPLY BATCH;

BEGIN BATCH
INSERT INTO tribe_users (user_id, user_name, email, date_created, last_login)
  VALUES(22222222-2222-2222-2222-222222222222, 'User2', 'user2@jive.org',
  toTimestamp(now()), toTimestamp(now()))
INSERT INTO tribe_user_credentials (email, password, user_id)
  VALUES ('user2@jive.org', 'password2',
  22222222-2222-2222-2222-222222222222)
APPLY BATCH;

BEGIN BATCH
INSERT INTO tribe_users (user_id, user_name, email, date_created, last_login)
  VALUES(33333333-3333-3333-3333-333333333333, 'User3', 'user3@jive.org',
  toTimestamp(now()), toTimestamp(now()))
INSERT INTO tribe_user_credentials (email, password, user_id)
  VALUES ('user3@jive.org', 'password3',
  33333333-3333-3333-3333-333333333333)
APPLY BATCH;

BEGIN BATCH
INSERT INTO tribe_users (user_id, user_name, email, date_created, last_login)
  VALUES(44444444-4444-4444-4444-444444444444, 'User4', 'user4@jive.org',
  toTimestamp(now()), toTimestamp(now()))
INSERT INTO tribe_user_credentials (email, password, user_id)
  VALUES ('user4@jive.org', 'password4',
  44444444-4444-4444-4444-444444444444)
APPLY BATCH;

BEGIN BATCH
INSERT INTO tribe_users (user_id, user_name, email, date_created, last_login)
  VALUES(55555555-5555-5555-5555-555555555555, 'User5', 'user5@jive.org',
  toTimestamp(now()), toTimestamp(now()))
INSERT INTO tribe_user_credentials (email, password, user_id)
  VALUES ('user5@jive.org', 'password5',
  55555555-5555-5555-5555-555555555555)
APPLY BATCH;


INSERT INTO tribe_members (owner_id, member_ids)
VALUES (00000000-0000-0000-0000-000000000000,
    {11111111-1111-1111-1111-111111111111,
    22222222-2222-2222-2222-222222222222,
    33333333-3333-3333-3333-333333333333}
);

INSERT INTO tribe_members (owner_id, member_ids)
VALUES (22222222-2222-2222-2222-222222222222,
    {11111111-1111-1111-1111-111111111111,
    55555555-5555-5555-5555-555555555555}
);

INSERT INTO tribe_members (owner_id, member_ids)
VALUES (44444444-4444-4444-4444-444444444444,
    {00000000-0000-0000-0000-000000000000,
    22222222-2222-2222-2222-222222222222,
    55555555-5555-5555-5555-555555555555,
    33333333-3333-3333-3333-333333333333}
);

INSERT INTO tribe_user_location (user_id, created_at, location)
VALUES (00000000-0000-0000-0000-000000000000,
    toTimeStamp(now()),
    {latitude: 24.3059, longitude: 81.4812}
);

INSERT INTO tribe_user_location (user_id, created_at, location)
VALUES (11111111-1111-1111-1111-111111111111,
    toTimeStamp(now()),
    {latitude: 24.3416, longitude: 81.4727}
);

INSERT INTO tribe_user_location (user_id, created_at, location)
VALUES (22222222-2222-2222-2222-222222222222,
    toTimeStamp(now()),
    {latitude: 24.2903, longitude: 81.4259}
);

INSERT INTO tribe_user_location (user_id, created_at, location)
VALUES (33333333-3333-3333-3333-333333333333,
    toTimeStamp(now()),
    {latitude: 24.2907, longitude: 81.4201}
);

INSERT INTO tribe_user_location (user_id, created_at, location)
VALUES (44444444-4444-4444-4444-444444444444,
    toTimeStamp(now()),
    {latitude: 24.2620, longitude: 81.3839}
);

INSERT INTO tribe_user_location (user_id, created_at, location)
VALUES (55555555-5555-5555-5555-555555555555,
    toTimeStamp(now()),
    {latitude: 24.3732, longitude: 82.5219}
);

INSERT INTO tribe_messages (message_id, sender_id, receiver_id, body)
VALUES (uuid(), 00000000-0000-0000-0000-000000000000,
    22222222-2222-2222-2222-222222222222,
    'this is the message body text'
);
