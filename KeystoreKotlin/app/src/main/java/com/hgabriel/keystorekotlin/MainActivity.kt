package com.hgabriel.keystorekotlin

import android.os.Bundle
import android.support.v7.app.AppCompatActivity
import kotlinx.android.synthetic.main.activity_main.*
import java.util.*

class MainActivity : AppCompatActivity() {

    private val TEXT_LENGTH = 300
    private val ALLOWED_CHARACTERS = "0123456789 qwertyuiopasdfghjklzxcvbnm"
    private val keystoreService = KeyStoreService(this, "EXAMPLE_KEYSTORE")

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        setupView()
    }

    private fun setupView() {
        generate_button.setOnClickListener {
            plain_text.text = random(TEXT_LENGTH)
        }

        encrypt_button.setOnClickListener {
            encrypted_text.text = keystoreService.encryptData(plain_text.text.toString())
        }

        encrypt_bulk_button.setOnClickListener {
            encrypted_bulk_text.text = keystoreService.perfomRSAEncryption(plain_text.text.toString())
        }

        decrypt_button.setOnClickListener {
            decrypted_text.text = keystoreService.decryptData(encrypted_text.text.toString())
        }

        decrypt_bulk_button.setOnClickListener {
            decrypted_bulk_text.text = keystoreService.perfomRSADecryption(encrypted_bulk_text.text.toString())
        }
    }

    private fun random(sizeOfRandomString: Int): String {
        val random = Random()
        val sb = StringBuilder(sizeOfRandomString)
        for (i in 0 until sizeOfRandomString)
            sb.append(ALLOWED_CHARACTERS[random.nextInt(ALLOWED_CHARACTERS.length)])
        return sb.toString()
    }
}
