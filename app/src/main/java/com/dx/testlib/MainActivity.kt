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
import java.security.Key
import java.util.*
import javax.crypto.spec.SecretKeySpec

data class MyFileSettings(val settings : DESFireFile.FileSettings,val len:Int) {}

fun IDESFireEV2.getFileSettings(fileNo: Byte) : MyFileSettings {
    val response = this.reader.transceive(
        byteArrayOf(0x90.toByte(),0xF5.toByte(), 0x00, 0x00, 0x01, fileNo.toByte(), 0x00))

    val sw = response.takeLast(2).toByteArray()
    if (!Arrays.equals(sw, MainActivity.SW_SUCCESS)) {
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

class MainActivity : AppCompatActivity() {

    lateinit private var libInstance: NxpNfcLib

    companion object {
        const val licenseKey = "f00ce3219672be96dc487e971d62ff2f"
        const val TAG = "MainActivity "
        var objKEY_2KTDES: IKeyData? = null
        var objKEY_3DES: IKeyData? = null
        var objKEY_AES: IKeyData? = null
        var testKEY_AES: IKeyData? = null

        val SW_ERROR = byteArrayOf(0x91.toByte(), 0xAE.toByte())
        val SW_SUCCESS = byteArrayOf(0x91.toByte(), 0x00.toByte())

        val KEY_THREE_DES = byteArrayOf(
                0x00.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte(),
                0x00.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte(),
                0x00.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte(),
                0x00.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte())
        val KEY_2KTDES = byteArrayOf(
                0x00.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte(),
                0x00.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte(),
                0x00.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte(),
                0x00.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte(),
                0x00.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte(),
                0x00.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte())
        val KEY_AES = byteArrayOf(
                0xCA.toByte(), 0x2D.toByte(), 0xAE.toByte(), 0x50.toByte(),
                0x00.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte(),
                0x00.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte(),
                0x00.toByte(), 0x00.toByte(), 0x00.toByte(), 0x01.toByte())

        val TEST_KEY_AES = byteArrayOf(
                0x00.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte(),
                0x00.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte(),
                0x00.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte(),
                0x00.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte())

        val DEFAULT_KEY_2KTDES = byteArrayOf(
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00)

        val CURRENT_KEY_AES =  byteArrayOf(
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00)

        val timeOut = 2000
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        initializeLogging()
        initializeLibrary()

        val keyDataObjj = KeyData()
        var kk: Key = SecretKeySpec(KEY_THREE_DES, "DESede")
        keyDataObjj.key = kk
        objKEY_3DES = keyDataObjj

        val keyDataObj = KeyData()
        var k: Key = SecretKeySpec(KEY_2KTDES, "DESede")
        keyDataObj.key = k
        objKEY_2KTDES = keyDataObj

        var a = SecretKeySpec(KEY_AES, "AES")
        var b = KeyData()
        b.key = a
        objKEY_AES = b

        var aa = SecretKeySpec(KEY_AES, "AES")
        var bb = KeyData()
        bb.key = aa
        testKEY_AES = bb
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

                        readFromCard(desFireEV2)
                        //writeToCard(desFireEV2)

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

            val appAID = byteArrayOf(0x00, 0x00, 0x01)
            val fileNo = 0x00
            var keyNo = 0x00
            desFireEV2.selectApplication(appAID)
            desFireEV2.authenticate(keyNo, IDESFireEV1.AuthType.Native, KeyType.THREEDES, objKEY_3DES)

            val se = desFireEV2.getFileSettings(fileNo.toByte())
            val fileType = se.settings.type

            when (fileType) {
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
            desFireEV2.authenticate(keyNo, IDESFireEV1.AuthType.Native, KeyType.THREEDES, objKEY_2KTDES)
            //desFireEV2.authenticate(0, IDESFireEV1.AuthType.AES, KeyType.AES128, objKEY_AES)

            val app_Ids = desFireEV2.applicationIDs
            for (app_id in app_Ids) {
                val ids: ByteArray = Utilities.intToBytes(app_id, 3)
                val str: String = Utilities.byteToHexString(ids)
                Log.i(TAG,"AID: " + str)
            }

            // create new application
            val appAID = byteArrayOf(0x00, 0x00, 0x03)
            //val appSetting = EV2ApplicationKeySettings(byteArrayOf(0x3F, 0x05))

            val appSetting = EV2ApplicationKeySettings.Builder()
                .setMaxNumberOfApplicationKeys(10)
                //.setAppKeyChangeAccessRight(0x07)
                .setAppKeySettingsChangeable(true)
                .setAuthenticationRequiredForDirectoryConfigurationData(/*true*/ false)
                .setAuthenticationRequiredForFileManagement(/*true*/ false)
                .setAppMasterKeyChangeable(true)
                //.setKeyTypeOfApplicationKeys(KeyType.AES128)
                .build()

            desFireEV2.createApplication(appAID, appSetting)

            // select an application and authenticate to it
            desFireEV2.selectApplication(appAID)
            //desFireEV2.authenticate(0, IDESFireEV1.AuthType.Native, KeyType.TWO_KEY_THREEDES, objKEY_3DES)
            desFireEV2.authenticate(0, IDESFireEV1.AuthType.Native, KeyType.THREEDES, objKEY_3DES)
            //desFireEV2.authenticate(0, IDESFireEV1.AuthType.Native, KeyType.THREEDES, objKEY_2KTDES)
            //desFireEV2.authenticate(0, IDESFireEV1.AuthType.AES, KeyType.AES128, testKEY_AES)
            //desFireEV2.changeKey(0, KeyType.AES128, CURRENT_KEY_AES, DEFAULT_KEY_2KTDES, 0x01.toByte())

            // create a standard file under the application
            val fileSize = 7
            val fileNo = 0
            desFireEV2.createFile(
                fileNo,
                StdDataFileSettings(
                    IDESFireEV1.CommunicationType.Plain,
                    //0x03, 0x01, 0x05, 0x02,
                    0x01, 0x02, 0x03, 0x04,
                    fileSize)
            )

            keyNo = 0x02
            desFireEV2.authenticate(keyNo, IDESFireEV1.AuthType.Native, KeyType.THREEDES, objKEY_2KTDES)

            val content = byteArrayOf(0xFA.toByte(), 0xCE.toByte(), 0xBA.toByte(), 0xBE.toByte())
            val fileOffset = 0
            desFireEV2.writeData(fileNo, fileOffset, content)
            Log.i(TAG, "writing to file${fileNo} success:" + Utilities.byteToHexString(content))

        } catch (e: java.lang.Exception) {
            Log.i(TAG,e.message)
        }
    }

    private fun formatCard(desFireEV2: IDESFireEV2) {
        desFireEV2.reader.timeout = timeOut.toLong()
        desFireEV2.selectApplication(0)
        //desFireEV2.authenticate(0, IDESFireEV1.AuthType.Native, KeyType.THREEDES, objKEY_2KTDES)
        desFireEV2.authenticate(0, IDESFireEV1.AuthType.AES, KeyType.AES128, objKEY_AES)
        desFireEV2.format();
    }
}