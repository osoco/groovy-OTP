/*
 * ====================================================================
 *    ____  _________  _________
 *   / __ \/ ___/ __ \/ ___/ __ \
 *  / /_/ (__  ) /_/ / /__/ /_/ /
 *  \____/____/\____/\___/\____/
 *
 *  ~ La empresa de los programadores profesionales ~
 *
 *  | http://osoco.es
 *  |
 *  | Edificio Moma Lofts
 *  | Planta 3, Loft 18
 *  | Ctra. Mostoles-Villaviciosa, Km 0,2
 *  | Mostoles, Madrid 28935 Spain
 *
 * ====================================================================
 *
 * Copyright 2012 OSOCO. All Rights Reserved.
 *
 */
package es.osoco.oath.hotp

import spock.lang.Specification
import spock.lang.Unroll

class HOTPSpec extends Specification
{
    static String sharedSecret
    static int codeDigits = 6

    def setupSpec()
    {
        sharedSecret = '3132333435363738393031323334353637383930'
    }

    @Unroll
    def "HOTP interoperability test"()
    {
        given:
        def hexSecretKey = hexStr2Bytes(sharedSecret)

        expect:
        hotp == es.osoco.oath.hotp.OneTimePasswordAlgorithm.generateOTP( hexSecretKey, count, codeDigits, false)

        where:
        count | hotp
        0     | '755224'
        1     | '287082'
        2     | '359152'
        3     | '969429'
        4     | '338314'
        5     | '254676'
        6     | '287922'
        7     | '162583'
        8     | '399871'
        9     | '520489'
    }

    private static byte[] hexStr2Bytes(String hex){
        // Adding one byte to get the right conversion
        // Values starting with "0" can be converted
        byte[] bArray = new BigInteger("10" + hex,16).toByteArray()

        // Copy all the REAL bytes, not the "first"
        byte[] ret = new byte[bArray.length - 1]
        for (int i = 0; i < ret.length; i++)
            ret[i] = bArray[i+1]
        return ret
    }

}



