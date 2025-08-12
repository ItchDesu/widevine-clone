package com.example.drm

import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.util.Base64

/**
 * Simple client that requests a license from the demo server.
 */
object LicenseClient {
    @Throws(IOException::class)
    fun requestLicense(serverUrl: String, contentId: String): ByteArray {
        val url = URL("$serverUrl/license")
        val json = "{\"content_id\":\"$contentId\"}"

        val conn = url.openConnection() as HttpURLConnection
        conn.requestMethod = "POST"
        conn.doOutput = true
        conn.setRequestProperty("Content-Type", "application/json")
        conn.outputStream.use { it.write(json.toByteArray()) }

        if (conn.responseCode != 200) {
            throw IOException("Server returned ${'$'}{conn.responseCode}")
        }

        val response = conn.inputStream.bufferedReader().use { it.readText() }
        val match = Regex("\"license\"\\s*:\\s*\"([^\"]+)\"").find(response)
            ?: throw IOException("Invalid response: $response")
        val b64 = match.groupValues[1]
        return Base64.getDecoder().decode(b64)
    }
}
