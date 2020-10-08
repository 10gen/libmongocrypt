/*
 * Copyright 2020-present MongoDB, Inc.
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

#include "mongocrypt-kek-private.h"
#include "mongocrypt-private.h"
#include "mongocrypt-opts-private.h"

/* Possible documents to parse:
 * AWS
 *    provider: "aws"
 *    region: <string>
 *    key: <string>
 *    endpoint: <optional string>
 * Azure
 *    provider: "azure"
 *    keyVaultEndpoint: <string>
 *    keyName: <string>
 *    keyVersion: <optional string>
 * GCP
 *    projectId: <string>
 *    location: <string>
 *    keyRing: <string>
 *    keyName: <string>
 *    keyVersion: <string>
 *    endpoint: <optional string>
 * Local
 *    provider: "local"
 */
bool
_mongocrypt_kek_parse_owned (const bson_t *bson,
                             _mongocrypt_kek_t *kek,
                             mongocrypt_status_t *status)
{
   char *kms_provider = NULL;
   bool ret = false;

   if (!_mongocrypt_parse_required_utf8 (
          bson, "provider", &kms_provider, status)) {
      goto done;
   }

   if (0 == strcmp (kms_provider, "aws")) {
      kek->kms_provider = MONGOCRYPT_KMS_PROVIDER_AWS;
      if (!_mongocrypt_parse_required_utf8 (
             bson, "key", &kek->provider.aws.cmk, status)) {
         goto done;
      }
      if (!_mongocrypt_parse_required_utf8 (
             bson, "region", &kek->provider.aws.region, status)) {
         goto done;
      }
      if (!_mongocrypt_parse_optional_endpoint (
             bson, "endpoint", &kek->provider.aws.endpoint, status)) {
         goto done;
      }
   } else if (0 == strcmp (kms_provider, "local")) {
      kek->kms_provider = MONGOCRYPT_KMS_PROVIDER_LOCAL;
   } else if (0 == strcmp (kms_provider, "azure")) {
      kek->kms_provider = MONGOCRYPT_KMS_PROVIDER_AZURE;
      if (!_mongocrypt_parse_required_endpoint (
             bson,
             "keyVaultEndpoint",
             &kek->provider.azure.key_vault_endpoint,
             status)) {
         goto done;
      }

      if (!_mongocrypt_parse_required_utf8 (
             bson, "keyName", &kek->provider.azure.key_name, status)) {
         goto done;
      }

      if (!_mongocrypt_parse_optional_utf8 (
             bson, "keyVersion", &kek->provider.azure.key_version, status)) {
         goto done;
      }
   } else if (0 == strcmp (kms_provider, "gcp")) {
      kek->kms_provider = MONGOCRYPT_KMS_PROVIDER_GCP;
      if (!_mongocrypt_parse_optional_endpoint (
             bson, "endpoint", &kek->provider.gcp.endpoint, status)) {
         goto done;
      }

      if (!_mongocrypt_parse_required_utf8 (
             bson, "projectId", &kek->provider.gcp.project_id, status)) {
         goto done;
      }

      if (!_mongocrypt_parse_required_utf8 (
             bson, "location", &kek->provider.gcp.location, status)) {
         goto done;
      }

      if (!_mongocrypt_parse_required_utf8 (
             bson, "keyRing", &kek->provider.gcp.key_ring, status)) {
         goto done;
      }

      if (!_mongocrypt_parse_required_utf8 (
             bson, "keyName", &kek->provider.gcp.key_name, status)) {
         goto done;
      }

      if (!_mongocrypt_parse_optional_utf8 (
             bson, "keyVersion", &kek->provider.gcp.key_version, status)) {
         goto done;
      }
   } else {
      CLIENT_ERR ("unrecognized KMS provider: %s", kms_provider);
      goto done;
   }

   ret = true;
done:
   bson_free (kms_provider);
   return ret;
}

bool
_mongocrypt_kek_append (const _mongocrypt_kek_t *kek,
                        bson_t *bson,
                        mongocrypt_status_t *status)
{
   if (kek->kms_provider == MONGOCRYPT_KMS_PROVIDER_AWS) {
      BSON_APPEND_UTF8 (bson, "provider", "aws");
      BSON_APPEND_UTF8 (bson, "region", kek->provider.aws.region);
      BSON_APPEND_UTF8 (bson, "key", kek->provider.aws.cmk);
      if (kek->provider.aws.endpoint) {
         BSON_APPEND_UTF8 (
            bson, "endpoint", kek->provider.aws.endpoint->host_and_port);
      }
   } else if (kek->kms_provider == MONGOCRYPT_KMS_PROVIDER_LOCAL) {
      BSON_APPEND_UTF8 (bson, "provider", "local");
   } else if (kek->kms_provider == MONGOCRYPT_KMS_PROVIDER_AZURE) {
      BSON_APPEND_UTF8 (bson, "provider", "azure");
      BSON_APPEND_UTF8 (bson,
                        "keyVaultEndpoint",
                        kek->provider.azure.key_vault_endpoint->host_and_port);
      BSON_APPEND_UTF8 (bson, "keyName", kek->provider.azure.key_name);
      if (kek->provider.azure.key_version) {
         BSON_APPEND_UTF8 (bson, "keyVersion", kek->provider.azure.key_version);
      }
   } else if (kek->kms_provider == MONGOCRYPT_KMS_PROVIDER_GCP) {
      BSON_APPEND_UTF8 (bson, "provider", "gcp");
      BSON_APPEND_UTF8 (bson, "projectId", kek->provider.gcp.project_id);
      BSON_APPEND_UTF8 (bson, "location", kek->provider.gcp.location);
      BSON_APPEND_UTF8 (bson, "keyRing", kek->provider.gcp.key_ring);
      BSON_APPEND_UTF8 (bson, "keyName", kek->provider.gcp.key_name);
      if (kek->provider.gcp.key_version) {
         BSON_APPEND_UTF8 (bson, "keyVersion", kek->provider.gcp.key_version);
      }
      if (kek->provider.gcp.endpoint) {
         BSON_APPEND_UTF8 (
            bson, "endpoint", kek->provider.gcp.endpoint->host_and_port);
      }
   }
   return true;
}

void
_mongocrypt_kek_copy_to (const _mongocrypt_kek_t *src, _mongocrypt_kek_t *dst)
{
   if (src->kms_provider == MONGOCRYPT_KMS_PROVIDER_AWS) {
      dst->provider.aws.cmk = bson_strdup (src->provider.aws.cmk);
      dst->provider.aws.region = bson_strdup (src->provider.aws.region);
      dst->provider.aws.endpoint =
         _mongocrypt_endpoint_copy (src->provider.aws.endpoint);
   } else if (src->kms_provider == MONGOCRYPT_KMS_PROVIDER_AZURE) {
      dst->provider.azure.key_vault_endpoint =
         _mongocrypt_endpoint_copy (src->provider.azure.key_vault_endpoint);
      dst->provider.azure.key_name = bson_strdup (src->provider.azure.key_name);
      dst->provider.azure.key_version =
         bson_strdup (src->provider.azure.key_version);
   } else if (src->kms_provider == MONGOCRYPT_KMS_PROVIDER_GCP) {
      dst->provider.gcp.project_id = bson_strdup (src->provider.gcp.project_id);
      dst->provider.gcp.location = bson_strdup (src->provider.gcp.location);
      dst->provider.gcp.key_ring = bson_strdup (src->provider.gcp.key_ring);
      dst->provider.gcp.key_name = bson_strdup (src->provider.gcp.key_name);
      dst->provider.gcp.key_version =
         bson_strdup (src->provider.gcp.key_version);
      dst->provider.gcp.endpoint =
         _mongocrypt_endpoint_copy (src->provider.gcp.endpoint);
   }
   dst->kms_provider = src->kms_provider;
}

void
_mongocrypt_kek_cleanup (_mongocrypt_kek_t *kek)
{
   if (kek->kms_provider == MONGOCRYPT_KMS_PROVIDER_AWS) {
      bson_free (kek->provider.aws.cmk);
      bson_free (kek->provider.aws.region);
      _mongocrypt_endpoint_destroy (kek->provider.aws.endpoint);
   } else if (kek->kms_provider == MONGOCRYPT_KMS_PROVIDER_AZURE) {
      _mongocrypt_endpoint_destroy (kek->provider.azure.key_vault_endpoint);
      bson_free (kek->provider.azure.key_name);
      bson_free (kek->provider.azure.key_version);
   } else if (kek->kms_provider == MONGOCRYPT_KMS_PROVIDER_GCP) {
      bson_free (kek->provider.gcp.project_id);
      bson_free (kek->provider.gcp.location);
      bson_free (kek->provider.gcp.key_ring);
      bson_free (kek->provider.gcp.key_name);
      bson_free (kek->provider.gcp.key_version);
      _mongocrypt_endpoint_destroy (kek->provider.gcp.endpoint);
   }
   return;
}