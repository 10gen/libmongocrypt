/*
 * Copyright 2019–present MongoDB, Inc.
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

using System;
using System.Runtime.InteropServices;

namespace MongoDB.Libmongocrypt
{
    /// <summary>
    /// CryptClient represents a session with libmongocrypt.
    /// 
    /// It can be used to encrypt and decrypt documents.
    /// </summary>
    /// <seealso cref="System.IDisposable" />
    public class CryptClient : IDisposable, IStatus
    {
        private MongoCryptSafeHandle _handle;
        private Status _status;

        internal CryptClient(MongoCryptSafeHandle handle, Status status)
        {
            _handle = handle;
            _status = status;
        }

        /// <summary>
        /// Starts the create data key context.
        /// </summary>
        /// <param name="keyId">The key identifier.</param>
        /// <returns>A crypt context for creating a data key</returns>
        public CryptContext StartCreateDataKeyContext(KmsKeyId keyId)
        {
            ContextSafeHandle handle = Library.mongocrypt_ctx_new(_handle);

            keyId.SetCredentials(handle, _status);

            handle.Check(_status, Library.mongocrypt_ctx_datakey_init(handle));

            return new CryptContext(handle);
        }

        /// <summary>
        /// Starts the encryption context.
        /// </summary>
        /// <param name="db">The database of the collection.</param>
        /// <param name="command">The command.</param>
        /// <returns>A encryption context.</returns>
        public CryptContext StartEncryptionContext(string db, byte[] command)
        {
            ContextSafeHandle handle = Library.mongocrypt_ctx_new(_handle);

            IntPtr stringPointer = (IntPtr)Marshal.StringToHGlobalAnsi(db);

            try
            {
                unsafe
                {
                    fixed (byte* c = command)
                    {
                        var commandPtr = (IntPtr)c;
                        using (var pinnedCommand = new PinnedBinary(commandPtr, (uint)command.Length))
                        {
                            // Let mongocrypt run strlen
                            handle.Check(_status, Library.mongocrypt_ctx_encrypt_init(handle, stringPointer, -1, pinnedCommand.Handle));
                        }
                    }
                }
            }
            finally
            {
                Marshal.FreeHGlobal(stringPointer);
            }

            return new CryptContext(handle);
        }

        /// <summary>
        /// Starts an explicit encryption context.
        /// </summary>
        /// <param name="key">The key id.</param>
        /// <param name="encryptionAlgorithm">The encryption algorithm.</param>
        /// <param name="message">The BSON message.</param>
        /// <returns>A encryption context. </returns>
        public CryptContext StartExplicitEncryptionContextWithKeyId(byte[] keyId, string encryptionAlgorithm, byte[] message)
        {
            ContextSafeHandle handle = Library.mongocrypt_ctx_new(_handle);

            unsafe
            {
                fixed (byte* p = keyId)
                {
                    IntPtr ptr = (IntPtr)p;
                    using (PinnedBinary pinned = new PinnedBinary(ptr, (uint)keyId.Length))
                    {
                        handle.Check(_status, Library.mongocrypt_ctx_setopt_key_id(handle, pinned.Handle));
                    }
                }
            }

            handle.Check(_status, Library.mongocrypt_ctx_setopt_algorithm(handle, encryptionAlgorithm, -1));

            unsafe
            {
                fixed (byte* p = message)
                {
                    IntPtr ptr = (IntPtr)p;
                    using (PinnedBinary pinned = new PinnedBinary(ptr, (uint)message.Length))
                    {
                        handle.Check(_status, Library.mongocrypt_ctx_explicit_encrypt_init(handle, pinned.Handle));
                    }
                }
            }

            return new CryptContext(handle);
        }

        /// <summary>
        /// Starts an explicit encryption context.
        /// </summary>
        /// <param name="keyAltName">The alternative key name.</param>
        /// <param name="encryptionAlgorithm">The algorithm.</param>
        /// <param name="message">The BSON message.</param>
        /// <returns>A encryption context. </returns>
        public CryptContext StartExplicitEncryptionContextWithKeyAltName(byte[] keyAltName, string encryptionAlgorithm, byte[] message)
        {
            ContextSafeHandle handle = Library.mongocrypt_ctx_new(_handle);
            unsafe
            {
                fixed (byte* p = keyAltName)
                {
                    IntPtr ptr = (IntPtr)p;
                    using (PinnedBinary pinned = new PinnedBinary(ptr, (uint)keyAltName.Length))
                    {
                        handle.Check(_status, Library.mongocrypt_ctx_setopt_key_alt_name(handle, pinned.Handle));
                    }
                }
            }

            handle.Check(_status, Library.mongocrypt_ctx_setopt_algorithm(handle, encryptionAlgorithm, -1));

            unsafe
            {
                fixed (byte* p = message)
                {
                    IntPtr ptr = (IntPtr)p;
                    using (PinnedBinary pinned = new PinnedBinary(ptr, (uint)message.Length))
                    {
                        handle.Check(_status, Library.mongocrypt_ctx_explicit_encrypt_init(handle, pinned.Handle));
                    }
                }
            }

            return new CryptContext(handle);
        }

        /// <summary>
        /// Starts the decryption context.
        /// </summary>
        /// <param name="buffer">The bson document to decrypt.</param>
        /// <returns>A decryption context</returns>
        public CryptContext StartDecryptionContext(byte[] buffer)
        {
            ContextSafeHandle handle = Library.mongocrypt_ctx_new(_handle);

            GCHandle gch = GCHandle.Alloc(buffer, GCHandleType.Pinned);

            unsafe
            {
                fixed (byte* p = buffer)
                {
                    IntPtr ptr = (IntPtr)p;
                    using (PinnedBinary pinned = new PinnedBinary(ptr, (uint)buffer.Length))
                    {
                        handle.Check(_status, Library.mongocrypt_ctx_decrypt_init(handle, pinned.Handle));
                    }
                }
            }

            return new CryptContext(handle);
        }

        /// <summary>
        /// Starts an explicit decryption context.
        /// </summary>
        /// <param name="buffer">The buffer.</param>
        /// <returns>A encryption context</returns>
        public CryptContext StartExplicitDecryptionContext(byte[] buffer)
        {
            ContextSafeHandle handle = Library.mongocrypt_ctx_new(_handle);

            unsafe
            {
                fixed (byte* p = buffer)
                {
                    IntPtr ptr = (IntPtr)p;
                    using (PinnedBinary pinned = new PinnedBinary(ptr, (uint)buffer.Length))
                    {
                        // Let mongocrypt run strlen
                        handle.Check(_status, Library.mongocrypt_ctx_explicit_decrypt_init(handle, pinned.Handle));
                    }
                }
            }

            return new CryptContext(handle);
        }


        void IStatus.Check(Status status)
        {
            Library.mongocrypt_status(_handle, status.Handle);
        }

        #region IDisposable
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            // Adapted from: https://docs.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.safehandle?view=netcore-3.0
            if (_handle != null && !_handle.IsInvalid)
            {
                // Free the handle
                _handle.Dispose();
            }
        }
        #endregion

        private void Check(bool success)
        {
            if (!success)
            {
                _status.Check(this);
            }
        }
    }
}
