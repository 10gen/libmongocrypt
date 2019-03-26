/*
 * Copyright 2019-present MongoDB, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <bson/bson.h>

#include "mongocrypt.h"
#include "mongocrypt-ctx-private.h"
#include "mongocrypt-private.h"
#include "mongocrypt-key-broker-private.h"


/* A failure status has already been set. */
bool
_mongocrypt_ctx_fail (mongocrypt_ctx_t *ctx)
{
   BSON_ASSERT (!mongocrypt_status_ok (ctx->status));
   ctx->state = MONGOCRYPT_CTX_ERROR;
   return false;
}


bool
_mongocrypt_ctx_fail_w_msg (mongocrypt_ctx_t *ctx, const char *msg)
{
   _mongocrypt_set_error (ctx->status,
                          MONGOCRYPT_STATUS_ERROR_CLIENT,
                          MONGOCRYPT_GENERIC_ERROR_CODE,
                          "%s",
                          msg);
   return _mongocrypt_ctx_fail (ctx);
}


mongocrypt_ctx_t *
mongocrypt_ctx_new (mongocrypt_t *crypt)
{
   mongocrypt_ctx_t *ctx;
   int ctx_size;

   ctx_size = sizeof (_mongocrypt_ctx_encrypt_t);
   if (sizeof (_mongocrypt_ctx_decrypt_t) > ctx_size) {
      ctx_size = sizeof (_mongocrypt_ctx_decrypt_t);
   }
   ctx = bson_malloc0 (ctx_size);
   ctx->crypt = crypt;
   /* TODO: whether the key broker aborts due to missing keys might be
    * responsibility of sub-contexts. */
   _mongocrypt_key_broker_init (&ctx->kb, true, crypt->opts);
   ctx->status = mongocrypt_status_new ();
   return ctx;
}


/* Common to both encrypt and decrypt context. */
static bool
_mongo_op_keys (mongocrypt_ctx_t *ctx, mongocrypt_binary_t *out)
{
   /* Construct the find filter to fetch keys. */
   if (!_mongocrypt_key_broker_filter (&ctx->kb, out)) {
      BSON_ASSERT (!_mongocrypt_key_broker_status (&ctx->kb, ctx->status));
      return _mongocrypt_ctx_fail (ctx);
   }
   return true;
}


static bool
_mongo_feed_keys (mongocrypt_ctx_t *ctx, mongocrypt_binary_t *in)
{
   _mongocrypt_buffer_t buf;

   _mongocrypt_buffer_from_binary (&buf, in);
   if (!_mongocrypt_key_broker_add_doc (&ctx->kb, &buf)) {
      BSON_ASSERT (!_mongocrypt_key_broker_status (&ctx->kb, ctx->status));
      return _mongocrypt_ctx_fail (ctx);
   }
   return true;
}


static bool
_mongo_done_keys (mongocrypt_ctx_t *ctx)
{
   ctx->state = MONGOCRYPT_CTX_NEED_KMS;
   if (!_mongocrypt_key_broker_done_adding_docs (&ctx->kb)) {
      BSON_ASSERT (!_mongocrypt_key_broker_status (&ctx->kb, ctx->status));
      return _mongocrypt_ctx_fail (ctx);
   }
   return true;
}


bool
mongocrypt_ctx_mongo_op (mongocrypt_ctx_t *ctx, mongocrypt_binary_t *out)
{
   _mongocrypt_ctx_mongo_op_fn callme;

   callme = NULL;
   switch (ctx->state) {
   case MONGOCRYPT_CTX_NEED_MONGO_COLLINFO:
      callme = ctx->vtable.mongo_op_collinfo;
      break;
   case MONGOCRYPT_CTX_NEED_MONGO_MARKINGS:
      callme = ctx->vtable.mongo_op_markings;
      break;
   case MONGOCRYPT_CTX_NEED_MONGO_KEYS:
      callme = _mongo_op_keys;
      break;
   case MONGOCRYPT_CTX_NEED_KMS:
   case MONGOCRYPT_CTX_ERROR:
   case MONGOCRYPT_CTX_DONE:
   case MONGOCRYPT_CTX_READY:
   case MONGOCRYPT_CTX_NOTHING_TO_DO:
      break;
   }
   if (NULL == callme) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "wrong state");
   }
   return callme (ctx, out);
}


bool
mongocrypt_ctx_mongo_feed (mongocrypt_ctx_t *ctx, mongocrypt_binary_t *in)
{
   _mongocrypt_ctx_mongo_feed_fn callme;

   callme = NULL;
   switch (ctx->state) {
   case MONGOCRYPT_CTX_NEED_MONGO_COLLINFO:
      callme = ctx->vtable.mongo_feed_collinfo;
      break;
   case MONGOCRYPT_CTX_NEED_MONGO_MARKINGS:
      callme = ctx->vtable.mongo_feed_markings;
      break;
   case MONGOCRYPT_CTX_NEED_MONGO_KEYS:
      callme = _mongo_feed_keys;
      break;
   case MONGOCRYPT_CTX_NEED_KMS:
   case MONGOCRYPT_CTX_ERROR:
   case MONGOCRYPT_CTX_DONE:
   case MONGOCRYPT_CTX_READY:
   case MONGOCRYPT_CTX_NOTHING_TO_DO:
      break;
   }

   if (NULL == callme) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "wrong state");
   }
   return callme (ctx, in);
}


bool
mongocrypt_ctx_mongo_done (mongocrypt_ctx_t *ctx)
{
   _mongocrypt_ctx_mongo_done_fn callme;

   callme = NULL;
   switch (ctx->state) {
   case MONGOCRYPT_CTX_NEED_MONGO_COLLINFO:
      callme = ctx->vtable.mongo_done_collinfo;
      break;
   case MONGOCRYPT_CTX_NEED_MONGO_MARKINGS:
      callme = ctx->vtable.mongo_done_markings;
      break;
   case MONGOCRYPT_CTX_NEED_MONGO_KEYS:
      callme = _mongo_done_keys;
      break;
   case MONGOCRYPT_CTX_NEED_KMS:
   case MONGOCRYPT_CTX_ERROR:
   case MONGOCRYPT_CTX_DONE:
   case MONGOCRYPT_CTX_READY:
   case MONGOCRYPT_CTX_NOTHING_TO_DO:
      break;
   }

   if (NULL == callme) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "wrong state");
   }
   return callme (ctx);
}


mongocrypt_ctx_state_t
mongocrypt_ctx_state (mongocrypt_ctx_t *ctx)
{
   return ctx->state;
}


mongocrypt_kms_ctx_t *
mongocrypt_ctx_next_kms_ctx (mongocrypt_ctx_t *ctx)
{
   mongocrypt_kms_ctx_t *kms;

   kms = _mongocrypt_key_broker_next_kms (&ctx->kb);
   if (!kms) {
      return NULL;
   }
   return (mongocrypt_kms_ctx_t *) kms;
}


bool
mongocrypt_ctx_kms_done (mongocrypt_ctx_t *ctx)
{
   if (!_mongocrypt_key_broker_kms_done (&ctx->kb)) {
      BSON_ASSERT (!_mongocrypt_key_broker_status (&ctx->kb, ctx->status));
      return _mongocrypt_ctx_fail (ctx);
   }
   ctx->state = MONGOCRYPT_CTX_READY;
   return true;
}


bool
mongocrypt_ctx_finalize (mongocrypt_ctx_t *ctx, mongocrypt_binary_t *out)
{
   return ctx->vtable.finalize (ctx, out);
}


bool
mongocrypt_ctx_status (mongocrypt_ctx_t *ctx, mongocrypt_status_t *out)
{
   if (!mongocrypt_status_ok (ctx->status)) {
      _mongocrypt_status_copy_to (ctx->status, out);
      return false;
   }
   _mongocrypt_status_reset (out);
   return true;
}


void
mongocrypt_ctx_destroy (mongocrypt_ctx_t *ctx)
{
   if (!ctx) {
      return;
   }

   if (ctx->vtable.cleanup) {
      ctx->vtable.cleanup (ctx);
   }

   mongocrypt_status_destroy (ctx->status);
   _mongocrypt_key_broker_cleanup (&ctx->kb);
   bson_free (ctx);
   return;
}