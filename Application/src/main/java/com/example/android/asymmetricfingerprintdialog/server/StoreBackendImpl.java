/*
 * Copyright (C) 2015 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 */

package com.example.android.asymmetricfingerprintdialog.server;


import android.util.Log;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * A fake backend implementation of {@link StoreBackend}.
 */
public class StoreBackendImpl implements StoreBackend {

    private final Map<String, PublicKey> mPublicKeys = new HashMap<>();

    @Override
    public boolean verify(Transaction transaction, byte[] transactionSignature) {
        try {
            PublicKey publicKey = mPublicKeys.get(transaction.getUserId());
            if (publicKey == null) {
                return false;
            }
            Signature verificationFunction = Signature.getInstance("SHA256withECDSA");
            verificationFunction.initVerify(publicKey);
            verificationFunction.update(transaction.toByteArray());
            if (verificationFunction.verify(transactionSignature)) {
                // Transaction is verified with the public key associated with the user
                // Do some post purchase processing in the server
                return true;
            }
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            Log.e("CERTTEST", "exception: " + e.getLocalizedMessage());
        }
        return false;
    }

    @Override
    public boolean enroll(String userId, String password, PublicKey publicKey) {
        if (publicKey != null) {
            mPublicKeys.put(userId, publicKey);
        }
        // We just ignore the provided password here, but in real life, it is registered to the
        // backend.
        return true;
    }
}
