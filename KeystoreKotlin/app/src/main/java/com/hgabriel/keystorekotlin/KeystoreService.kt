package com.hgabriel.keystorekotlin

import android.annotation.TargetApi
import android.content.Context
import android.os.Build
import android.security.KeyPairGeneratorSpec
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.util.*
import javax.crypto.Cipher.*
import javax.security.auth.x500.X500Principal


/**
 * Created by hgabriel on 13/01/2018.
 *
 */
class KeyStoreService(private val context: Context, private val keyStoreAlias: String) {

    private val keyStore: KeyStore

    private val KEYSTORE_PROVIDER = "AndroidKeyStore"
    private val RSA_CIPHER = "RSA/ECB/PKCS1Padding"
    private val KEY_LENGTH = 2048

    init {
        keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER)
        keyStore.load(null)
        if (!keyStore.containsAlias(keyStoreAlias)) this.createNewKey()
    }

    private fun createNewKey() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            createNewKeyM()
        } else {
            createNewKeyJ()
        }
    }

    @TargetApi(Build.VERSION_CODES.M)
    private fun createNewKeyM() {
        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, KEYSTORE_PROVIDER)
        generator.initialize(KeyGenParameterSpec.Builder(keyStoreAlias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_ECB)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                .build())
        generator.generateKeyPair()
    }

    @TargetApi(Build.VERSION_CODES.JELLY_BEAN_MR2)
    private fun createNewKeyJ() {
        val start = Calendar.getInstance()
        val end = Calendar.getInstance()
        end.add(Calendar.YEAR, 100)
        val generator = KeyPairGenerator.getInstance("RSA", KEYSTORE_PROVIDER)
        generator.initialize(KeyPairGeneratorSpec.Builder(this.context)
                .setAlias(keyStoreAlias)
                .setSubject(X500Principal("CN=Secured Preference Store, O=Android Authority"))
                .setSerialNumber(BigInteger.ONE)
                .setStartDate(start.time)
                .setEndDate(end.time)
                .build())
        generator.generateKeyPair()
    }

    fun encryptData(plainStr: String): String {
        val encryptKey = keyStore.getCertificate(keyStoreAlias).publicKey

        val cipher = getInstance(RSA_CIPHER)
        cipher.init(ENCRYPT_MODE, encryptKey)

        val message = plainStr.toByteArray(Charsets.ISO_8859_1)
        val baos = ByteArrayOutputStream()

        var limit = KEY_LENGTH / 8 - 11
        var position = 0
        while (position < message.size) {
            if (message.size - position < limit)
                limit = message.size - position
            baos.write(cipher.doFinal(message, position, limit))
            position += limit
        }

        return String(baos.toByteArray(), Charsets.ISO_8859_1)
    }

    fun decryptData(encryptedStr: String): String {
        val decryptKey = keyStore.getKey(keyStoreAlias, null) as PrivateKey

        val cipher = getInstance(RSA_CIPHER)
        cipher.init(DECRYPT_MODE, decryptKey)

        val encryptedMessage = encryptedStr.toByteArray(Charsets.ISO_8859_1)
        val baos = ByteArrayOutputStream()

        var limit = KEY_LENGTH / 8
        var position = 0
        while (position < encryptedMessage.size) {
            if (encryptedMessage.size - position < limit)
                limit = encryptedMessage.size - position
            val result = cipher.doFinal(encryptedMessage, position, limit)
            baos.write(result)
            position += limit
        }

        return String(baos.toByteArray(), Charsets.ISO_8859_1)
    }
}
