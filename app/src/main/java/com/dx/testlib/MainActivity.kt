package com.dx.testlib

import android.content.Intent
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import com.nxp.nfclib.CardType
import com.nxp.nfclib.KeyType
import com.nxp.nfclib.NxpNfcLib
import com.nxp.nfclib.defaultimpl.KeyData
import com.nxp.nfclib.desfire.*
import com.nxp.nfclib.desfire.DESFireFile.StdDataFileSettings
import com.nxp.nfclib.exceptions.NxpNfcLibException
import com.nxp.nfclib.interfaces.IKeyData
import com.nxp.nfclib.utils.Utilities
import dx.android.common.logger.Log
import dx.android.common.logger.LogFragment
import dx.android.common.logger.LogWrapper
import dx.android.common.logger.MessageOnlyLogFilter
import java.nio.ByteBuffer
import java.util.*
import javax.crypto.spec.SecretKeySpec

data class MyFileSettings(val settings : DESFireFile.FileSettings,val len:Int) {}

fun IDESFireEV2.getFileSettings(fileNo: Byte) : MyFileSettings {
    val response = this.reader.transceive(
        byteArrayOf(0x90.toByte(),0xF5.toByte(), 0x00, 0x00, 0x01, fileNo, 0x00))

    val sw = response.takeLast(2).toByteArray()
    if (!Arrays.equals(sw, byteArrayOf(0x91.toByte(), 0x00))) {
        throw SecurityException("Failed to get file size for file ${fileNo}")
    }

    val buf3 = response.slice(4..6).toByteArray()
    buf3.reverse()
    val buf4 = ByteArray(4)
    buf3.copyInto(buf4,1, 0, buf3.size)
    val fileSize = ByteBuffer.wrap(buf4).int
    val fs = this.getFileSettings(fileNo.toInt())
    val settings = StdDataFileSettings(
            fs.comSettings,
            fs.readAccess,
            fs.writeAccess,
            fs.readWriteAccess,
            fs.changeAccess,
            fileSize)

    return MyFileSettings(settings, fileSize)
}

data class KeyElem (val keytype: KeyType, val keydata: IKeyData, val keybuf:ByteArray, val authtype:IDESFireEV1.AuthType)

class MainActivity : AppCompatActivity() {

    lateinit private var libInstance: NxpNfcLib

    var keymap = HashMap<String, KeyElem>()

    companion object {
        val APP01 = byteArrayOf(0x00, 0x00, 0x01)
        val APP02 = byteArrayOf(0x00, 0x00, 0x02)
        val APP03 = byteArrayOf(0x00, 0x00, 0x03)
        val APP04 = byteArrayOf(0x00, 0x00, 0x04)
        val APP05 = byteArrayOf(0x00, 0x00, 0x05)

        val fileContent = byteArrayOf(0xFA.toByte(), 0xCE.toByte(), 0xBA.toByte(), 0xBE.toByte())
        const val licenseKey = "f00ce3219672be96dc487e971d62ff2f"
        const val TAG = "MainActivity "

        var key1: IKeyData? = null
        var key2: IKeyData? = null
        var key3: IKeyData? = null
        var key4: IKeyData? = null
        var key5: IKeyData? = null
        var key6: IKeyData? = null
        var key7: IKeyData? = null

        val keybuf1 = byteArrayOf( // AES default
                0x00.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte(),
                0x00.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte(),
                0x00.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte(),
                0x00.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte())

        val keybuf2 = byteArrayOf( // THREEDES default
                0x00.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte(),
                0x00.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte(),
                0x00.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte(),
                0x00.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte())

        val keybuf3 = byteArrayOf(
                0xA0.toByte(), 0xA1.toByte(), 0xA2.toByte(), 0xA3.toByte(),
                0xA4.toByte(), 0xA5.toByte(), 0xA6.toByte(), 0xA7.toByte(),
                0xA8.toByte(), 0xA9.toByte(), 0xAA.toByte(), 0xAB.toByte(),
                0xAC.toByte(), 0xAD.toByte(), 0xAE.toByte(), 0xAF.toByte())

        val keybuf4 = byteArrayOf(
                0xB0.toByte(), 0xB1.toByte(), 0xB2.toByte(), 0xB3.toByte(),
                0xB4.toByte(), 0xB5.toByte(), 0xB6.toByte(), 0xB7.toByte(),
                0xB8.toByte(), 0xB9.toByte(), 0xBA.toByte(), 0xBB.toByte(),
                0xBC.toByte(), 0xBD.toByte(), 0xBE.toByte(), 0xBF.toByte())

        val keybuf5 = byteArrayOf( // other card's PICC AES key
                0xCA.toByte(), 0x2D.toByte(), 0xAE.toByte(), 0x50.toByte(),
                0x00.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte(),
                0x00.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte(),
                0x00.toByte(), 0x00.toByte(), 0x00.toByte(), 0x01.toByte())

        val keybuf6 = byteArrayOf( // THREE_KEY_3DES default
                0x00.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte(),
                0x00.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte(),
                0x00.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte(),
                0x00.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte(),
                0x00.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte(),
                0x00.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte())

        val keybuf7 = byteArrayOf(
                0xC0.toByte(), 0xC1.toByte(), 0xC2.toByte(), 0xC3.toByte(),
                0xC4.toByte(), 0xC5.toByte(), 0xC6.toByte(), 0xC7.toByte(),
                0xC8.toByte(), 0xC9.toByte(), 0xCA.toByte(), 0xCB.toByte(),
                0xCC.toByte(), 0xCD.toByte(), 0xCE.toByte(), 0xCF.toByte())

        val timeOut = 2000
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        initializeLogging()
        initializeLibrary()
        initializeKeys()
    }

    override fun onResume() {
        super.onResume()
        libInstance.startForeGroundDispatch()
    }

    override fun onPause() {
        super.onPause()
        libInstance.stopForeGroundDispatch()
    }

    override fun onNewIntent(intent: Intent?) {
        super.onNewIntent(intent)
        if (intent != null) {
            checkCard(intent)
        }
    }

    // Create a chain of targets that will receive log data
    private fun initializeLogging() {
        val msgFilter = MessageOnlyLogFilter()
        val logFragment = supportFragmentManager.findFragmentById(R.id.mylogfragment) as LogFragment
        msgFilter.next = logFragment.logView

        val logWrapper = LogWrapper()
        logWrapper.next = msgFilter

        Log.logNode = logWrapper
    }

    private fun initializeLibrary() {
        libInstance = NxpNfcLib.getInstance()
        try {
            libInstance.registerActivity(this, licenseKey)
        } catch (ex: NxpNfcLibException) {
            Log.i(TAG,ex.message)
        } catch (e: Exception) {
            Log.i(TAG,e.message)
        }
    }

    private fun initializeKeys() {

        val kd1 = KeyData()
        kd1.key = SecretKeySpec(keybuf1, "AES")
        key1 = kd1

        val kd2 = KeyData()
        kd2.key = SecretKeySpec(keybuf2, "DESede")
        key2 = kd2

        val kd3 = KeyData()
        kd3.key = SecretKeySpec(keybuf3, "DESede")
        key3 = kd3

        val kd4 = KeyData()
        kd4.key = SecretKeySpec(keybuf4, "DESede")
        key4 = kd4

        var kd5 = KeyData()
        kd5.key = SecretKeySpec(keybuf5, "AES")
        key5 = kd5

        var kd6 = KeyData()
        kd6.key = SecretKeySpec(keybuf6, "DESede") // ?!?
        key6 = kd6

        var kd7 = KeyData()
        kd7.key = SecretKeySpec(keybuf7, "AES")
        key7 = kd7

        with (keymap) {
            put("key1", KeyElem(KeyType.AES128, key1 as KeyData, keybuf1, IDESFireEV1.AuthType.AES))
            put("key2", KeyElem(KeyType.THREEDES, key2 as KeyData, keybuf2, IDESFireEV1.AuthType.Native))
            put("key3", KeyElem(KeyType.TWO_KEY_THREEDES, key3 as KeyData, keybuf3, IDESFireEV1.AuthType.Native))
            put("key4", KeyElem(KeyType.TWO_KEY_THREEDES, key4 as KeyData, keybuf4, IDESFireEV1.AuthType.Native))
            put("key5", KeyElem(KeyType.AES128, key5 as KeyData, keybuf5, IDESFireEV1.AuthType.AES))
            put("key6", KeyElem(KeyType.THREE_KEY_THREEDES, key6 as KeyData, keybuf6, IDESFireEV1.AuthType.Native))
            put("key7", KeyElem(KeyType.AES128, key7 as KeyData, keybuf7, IDESFireEV1.AuthType.AES))
        }
    }

    private fun checkCard(intent: Intent) {
        val type = libInstance.getCardType(intent) //Get the type of the card

        if (type == CardType.UnknownCard) {
            Log.i(TAG,"Unknown card type")
            return
        }

        when (type) {
            CardType.DESFireEV2 -> {
                Log.i(TAG,type.tagName + " detected")
                val desFireEV2 = DESFireFactory.getInstance().getDESFireEV2(libInstance.customModules)
                if (desFireEV2.subType == IDESFireEV2.SubType.MIFAREIdentity) {
                    Log.i(TAG,"IDESFireEV2.SubType.MIFAREIdentity")
                    val mfID = DESFireFactory.getInstance().getMIFAREIdentity(libInstance.customModules)
                    val fciData = mfID.selectMIFAREIdentityAppAndReturnFCI()
                    Log.i(TAG,Utilities.byteToHexString(fciData))
                } else {
                    try {
                        desFireEV2.reader.connect()
                        desFireEV2.reader.timeout = timeOut.toLong()

                        //readFromCard(desFireEV2)
                        //writeToCard(desFireEV2)
                        //createApp(desFireEV2)
                        //writeFile(desFireEV2)
                        //changePICCSettings(desFireEV2)
                        //changePICCKey(desFireEV2)
                        //formatCard(desFireEV2)
                        //formatCard2(desFireEV2)

                        //createApp2(desFireEV2)
                        //createFile(desFireEV2)
                        //changeApplicationKey(desFireEV2)
                        //readFile(desFireEV2)

                    } catch (t: Throwable) {
                        Log.i(TAG,"Unknown Error Tap Again")
                    }
                }
            }
            else -> {
                Log.i(TAG,type.tagName + " not implemented")
            }
        }
    }

    private fun readFromCard(desFireEV2: IDESFireEV2) {
        try {

            val fileNo = 0x00
            var keyNo = 0x01
            desFireEV2.selectApplication(APP03)
            desFireEV2.authenticate(keyNo, IDESFireEV1.AuthType.Native, KeyType.THREEDES, key2)

            val se = desFireEV2.getFileSettings(fileNo.toByte())

            when (se.settings.type) {
                DESFireFile.FileType.DataStandard, DESFireFile.FileType.DataBackup -> {

                    val ks = desFireEV2.keySettings
                    Log.i(TAG, "ks: " + Utilities.byteToHexString(ks.toByteArray()))

                    val fids = desFireEV2.fileIDs // {0}
                    Log.i(TAG, "file ids: " + Utilities.byteToHexString(fids))

                    val fileOffset = 0
                    val fileSize = se.len
                    val content = desFireEV2.readData(fileNo, fileOffset, fileSize)
                    Log.i(TAG, "File${fileNo} content: " + Utilities.byteToHexString(content))
                }

                else -> {
                    Log.i(TAG, "Other file type")
                }
            }

        } catch (e: java.lang.Exception) {
            Log.i(TAG,e.message)
        }
    }

    private fun changeApplicationSettings(desFireEV2: IDESFireEV2) {

        try {
            var keyNo = 0x00
            desFireEV2.selectApplication(APP01)
            desFireEV2.authenticate(keyNo, IDESFireEV1.AuthType.Native, KeyType.THREEDES, key2)

            val s = EV1PICCKeySettings.Builder()
                    .setAuthenticationRequiredForApplicationManagement(false)
                    .setAuthenticationRequiredForDirectoryConfigurationData(true)
                    .setPiccKeySettingsChangeable(true)
                    .setPiccMasterKeyChangeable(true)
                    .build()

            Log.i(TAG, "s = " + Utilities.byteToHexString(s.toByteArray()))
            desFireEV2.changeKeySettings(s)

        } catch (e: Exception) {
            Log.e(TAG, e.message)
        }
    }

    private fun AUTHENTICATE(desFireEV2: IDESFireEV2, key: String, keyNo: Int) {
        try {
            with(keymap[key]) {
                desFireEV2.authenticate(keyNo, this!!.authtype, this!!.keytype, keydata)
            }
        } catch (e: Exception) {
            Log.e(TAG, "authenticate failed: " + e.message)
            throw e
        }
    }

    private fun CHANGEKEY(desFireEV2: IDESFireEV2, changeNo: Int, oldKey:String, newKey:String, kvno:Byte) {
        try {
            val keytype = keymap[newKey]?.keytype
            val currentBuf = keymap[oldKey]?.keybuf
            val newBuf = keymap[newKey]?.keybuf
            desFireEV2.changeKey(changeNo, keytype, currentBuf, newBuf, kvno)
        } catch (e: java.lang.Exception) {
            Log.e(TAG, "changeKey failed: " + e.message)
            throw e
        }
    }

    private fun changeApplicationKey(desFireEV2: IDESFireEV2) {
        try {
            val kvno = 42
            val keyNo = 7
            val changeNo = 5

            /**
             * Application change key compatbility:

                THREEDES <-------------> TWO_KEY_THREEDES
                AES <------------------> AES
                THREE_KEY_THREEDES <---> THREE_KEY_THREEDES
             */

            desFireEV2.selectApplication(APP01)
            AUTHENTICATE(desFireEV2, "key1", keyNo)
            CHANGEKEY(desFireEV2, changeNo, "key1", "key7", kvno.toByte())

            /*
            val appSetting = EV2ApplicationKeySettings.Builder()
                    .setAppKeySettingsChangeable(true)
                    .setAuthenticationRequiredForDirectoryConfigurationData(true)
                    .setAuthenticationRequiredForFileManagement(false)
                    .setAppMasterKeyChangeable(true)
                    .setAppKeyChangeAccessRight(0x7)
                    .build()

            desFireEV2.changeKeySettings(appSetting)
             */

        } catch (e: Exception) {
            Log.e(TAG, e.message)
        }
    }

    private fun changePICCKey(desFireEV2: IDESFireEV2) {
        try {
            val keyNo = 0
            desFireEV2.selectApplication(0)
            desFireEV2.authenticate(keyNo, IDESFireEV1.AuthType.Native, KeyType.TWO_KEY_THREEDES, key4)
            desFireEV2.changeKey(keyNo, KeyType.THREEDES, keybuf3, keybuf2, 0x00)
        } catch (e: Exception) {
            Log.e(TAG, e.message)
        }
    }

    private fun changePICCSettings(desFireEV2: IDESFireEV2) {

        try {
            var keyNo = 0x00
            desFireEV2.selectApplication(0)
            desFireEV2.authenticate(keyNo, IDESFireEV1.AuthType.Native, KeyType.TWO_KEY_THREEDES, key4)

            val s = EV1PICCKeySettings.Builder()
                    .setAuthenticationRequiredForApplicationManagement(false)
                    .setAuthenticationRequiredForDirectoryConfigurationData(true)
                    .setPiccKeySettingsChangeable(true)
                    .setPiccMasterKeyChangeable(true)
                    .build()

            Log.i(TAG, "s = " + Utilities.byteToHexString(s.toByteArray()))
            desFireEV2.changeKeySettings(s)

        } catch (e: Exception) {
            Log.e(TAG, e.message)
        }
    }

    private fun createApp(desFireEV2: IDESFireEV2) {

        try {

            var keyNo = 0x00
            desFireEV2.selectApplication(0)
            desFireEV2.authenticate(keyNo, IDESFireEV1.AuthType.Native, KeyType.TWO_KEY_THREEDES, key4)

            val appSetting = EV2ApplicationKeySettings.Builder()
                    .setMaxNumberOfApplicationKeys(10)
                    .setAppKeySettingsChangeable(true)
                    .setAuthenticationRequiredForDirectoryConfigurationData(true)
                    .setAuthenticationRequiredForFileManagement(false)
                    .setAppMasterKeyChangeable(true)
                    .build()

            desFireEV2.createApplication(APP01, appSetting)
            //desFireEV2.changeKey(0, KeyType.THREEDES, keybuf2, keybuf3, 0x42)

        } catch (e: java.lang.Exception) {
            Log.e(TAG, e.message)
        }
    }

    private fun createApp2(desFireEV2: IDESFireEV2) {

        try {

            var keyNo = 0x00
            desFireEV2.selectApplication(0)
            AUTHENTICATE(desFireEV2, "key2", keyNo)

            val appSetting = EV2ApplicationKeySettings.Builder()
                    .setMaxNumberOfApplicationKeys(10)
                    .setAppKeySettingsChangeable(true)
                    .setAuthenticationRequiredForDirectoryConfigurationData(false)
                    .setAuthenticationRequiredForFileManagement(false)
                    .setAppMasterKeyChangeable(true)
                    .setAppKeyChangeAccessRight(0x7)
                    .setKeyTypeOfApplicationKeys(KeyType.AES128)
                    .build()

            desFireEV2.createApplication(APP01, appSetting)

        } catch (e: java.lang.Exception) {
            Log.e(TAG, e.message)
        }
    }

    private fun createFile(desFireEV2: IDESFireEV2) {

        try {
            var keyNo = 0x00
            desFireEV2.selectApplication(APP01)
            AUTHENTICATE(desFireEV2, "key1", keyNo)

            val fileNo = 0x00
            val fileSize = 32
            desFireEV2.createFile(
                    fileNo,
                    StdDataFileSettings(
                            IDESFireEV1.CommunicationType.Enciphered,
                            0x01, 0x02, 0x03, 0x04,
                            fileSize)
            )
        } catch (e: Exception) {
            Log.e(TAG, e.message)
        }
    }

    private fun writeFile(desFireEV2: IDESFireEV2) {

        try {
            var keyNo = 0x02
            desFireEV2.selectApplication(APP01)
            desFireEV2.authenticate(keyNo, IDESFireEV1.AuthType.Native, KeyType.THREEDES, key2)

            val fileNo = 0
            val fileOffset = 0
            desFireEV2.writeData(fileNo, fileOffset, fileContent)
        } catch (e: Exception) {
            Log.e(TAG, e.message)
        }
    }

    private fun readFile(desFireEV2: IDESFireEV2) {

        try {
            var keyNo = 0x03
            desFireEV2.selectApplication(APP01)
            AUTHENTICATE(desFireEV2, "key2", keyNo)

            val fileNo = 0
            val se = desFireEV2.getFileSettings(fileNo.toByte())
            val fileOffset = 0
            val fileSize = se.len
            val content = desFireEV2.readData(fileNo, fileOffset, fileSize)
            Log.i(TAG, "content = ${Utilities.byteToHexString(content)}")
        } catch (e: Exception) {
            Log.e(TAG, e.message)
        }
    }

    private fun writeToCard(desFireEV2: IDESFireEV2) {

        val tagname = desFireEV2.type.tagName
        val tagUID = desFireEV2.uid
        val totalMem = desFireEV2.totalMemory
        val freeMem = desFireEV2.freeMemory

        Log.i(TAG,"uid: " + Utilities.byteToHexString(tagUID))
        Log.i(TAG,"totalMem: " + totalMem)
        Log.i(TAG,"freeMem: " + freeMem)

        try {
            val getVersion = desFireEV2.version

            if (getVersion[0] != 0x04.toByte()) {
                Log.i(TAG,"not from NXP")
            }

            if (getVersion[6] == 0x05.toByte()) {
                Log.i(TAG,"ISO/IEC 14443–4")
            } else {
                Log.i(TAG,"unknown")
            }

            var keyNo = 0
            desFireEV2.selectApplication(0)
            desFireEV2.authenticate(keyNo, IDESFireEV1.AuthType.Native, KeyType.THREEDES, key2)
            //desFireEV2.authenticate(0, IDESFireEV1.AuthType.AES, KeyType.AES128, key5)

            val app_Ids = desFireEV2.applicationIDs
            for (app_id in app_Ids) {
                val ids: ByteArray = Utilities.intToBytes(app_id, 3)
                val str: String = Utilities.byteToHexString(ids)
                Log.i(TAG,"AID: " + str)
            }

            // create new application
            //val appSetting = EV2ApplicationKeySettings(byteArrayOf(0x3F, 0x05))

            val appSetting = EV2ApplicationKeySettings.Builder()
                .setMaxNumberOfApplicationKeys(10)
                //.setAppKeyChangeAccessRight(0x7)
                .setAppKeySettingsChangeable(true)
                .setAuthenticationRequiredForDirectoryConfigurationData(true)
                .setAuthenticationRequiredForFileManagement(true)
                .setAppMasterKeyChangeable(true)
                //.setKeyTypeOfApplicationKeys(KeyType.AES128)
                .build()

            //desFireEV2.createApplication(appAID, appSetting)

            // select an application and authenticate to it
            desFireEV2.selectApplication(APP01)
            keyNo = 2
            desFireEV2.authenticate(keyNo, IDESFireEV1.AuthType.Native, KeyType.THREEDES, key2)

            // create a standard file under the application
            val fileSize = 7
            val fileNo = 0

            /*desFireEV2.createFile(
                fileNo,
                StdDataFileSettings(
                    IDESFireEV1.CommunicationType.Enciphered,
                    0x01, 0x02, 0x03, 0x04,
                    fileSize)
            )

            keyNo = 0x02
            desFireEV2.authenticate(keyNo, IDESFireEV1.AuthType.Native, KeyType.THREEDES, key2)*/

            val fileOffset = 0
            desFireEV2.writeData(fileNo, fileOffset, fileContent)
            Log.i(TAG, "writing to file${fileNo} success:" + Utilities.byteToHexString(fileContent))

        } catch (e: java.lang.Exception) {
            Log.i(TAG,e.message)
        }
    }

    private fun formatCard(desFireEV2: IDESFireEV2) {
        try {
            desFireEV2.selectApplication(0)
            desFireEV2.authenticate(0, IDESFireEV1.AuthType.Native, KeyType.TWO_KEY_THREEDES, key4)
            //desFireEV2.authenticate(0, IDESFireEV1.AuthType.AES, KeyType.AES128, key5)
            desFireEV2.format();
            Log.i(TAG, "Format success")
        } catch (e: java.lang.Exception) {
            Log.i(TAG,"Format failed: ${e.message}")
        }
    }

    private fun formatCard2(desFireEV2: IDESFireEV2) {

        val keys = listOf<ByteArray>(
                Utilities.stringToBytes("AABBCCDDEEFF0011A4BBCCDDEEFF0011"), // <---
                Utilities.stringToBytes("aabaccdceefe0010aabaccdceefe0010"),
                Utilities.stringToBytes("404142434445464748494a4b4c4d4e4F"),
                Utilities.stringToBytes("DEC0DE0102030405060708090A0B0C0D"),
                Utilities.stringToBytes("CAFEBABE0102030405060708090A0B0C"),
                Utilities.stringToBytes("C0FFEE0102030405060708090A0B0C0D"),
                Utilities.stringToBytes("B000B50102030405060708090A0B0C0D"),
                Utilities.stringToBytes("BADA550102030405060708090A0B0C0D"),
                Utilities.stringToBytes("FACADE0102030405060708090A0B0C0D"),
                Utilities.stringToBytes("0FF1C30102030405060708090A0B0C0D"),
                Utilities.stringToBytes("4CC3550102030405060708090A0B0C0D"),
                Utilities.stringToBytes("ADD1C70102030405060708090A0B0C0D"),
                Utilities.stringToBytes("09C0DE0102030405060708090A0B0C0D")
        )

        for (key in keys) {
            println("using key ${Utilities.byteToHexString(key)}")
            var KEY: IKeyData? = null
            val kd = KeyData()
            kd.key = SecretKeySpec(key, "DESede")
            KEY = kd

            try {
                desFireEV2.selectApplication(0)
                desFireEV2.authenticate(0, IDESFireEV1.AuthType.Native, KeyType.THREEDES, KEY)
                desFireEV2.format();
                Log.i(TAG, "Format success")
                break
            } catch (e: java.lang.Exception) {
            }
        }

        println("-- done --")
    }
}

