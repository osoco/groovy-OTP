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
package es.osoco.oath.totp

import spock.lang.Specification
import spock.lang.Unroll

class TOTPSpec extends Specification {

    static int T0
    static int timeStep
    static String digits
    static String seed
    static String seed32
    static String seed64

    def setupSpec() {
        T0 = 0
        timeStep = 30
        digits = '8'
        seed = "3132333435363738393031323334353637383930"
        seed32 =
            "3132333435363738393031323334353637383930" +
            "313233343536373839303132"
        seed64 = 
            "3132333435363738393031323334353637383930" +
            "3132333435363738393031323334353637383930" +
            "3132333435363738393031323334353637383930" + 
            "31323334"
    }

    @Unroll("OTP for T: #unixTime, K: #key and #crypto is #otp")
    def "TOTP interoperability test"() {
        given:
        def steps = stepsForTime(unixTime, T0, timeStep)

        expect:
        otp == TOTP.generateTOTP(key, steps, digits, crypto)

        where:
        key     | unixTime    | crypto      | otp
        seed    | 59          | 'HmacSHA1'  | '94287082'
        seed32  | 59          | 'HmacSHA256'| '46119246'
        seed64  | 59          | 'HmacSHA512'| '90693936'
        seed    | 1111111109  | 'HmacSHA1'  | '07081804'
        seed32  | 1111111109  | 'HmacSHA256'| '68084774'
        seed64  | 1111111109  | 'HmacSHA512'| '25091201'
        seed    | 1111111111  | 'HmacSHA1'  | '14050471'
        seed32  | 1111111111  | 'HmacSHA256'| '67062674'
        seed64  | 1111111111  | 'HmacSHA512'| '99943326'
        seed    | 1234567890  | 'HmacSHA1'  | '89005924'
        seed32  | 1234567890  | 'HmacSHA256'| '91819424'
        seed64  | 1234567890  | 'HmacSHA512'| '93441116'
        seed    | 2000000000  | 'HmacSHA1'  | '69279037'
        seed32  | 2000000000  | 'HmacSHA256'| '90698825'
        seed64  | 2000000000  | 'HmacSHA512'| '38618901'
        seed    | 20000000000 | 'HmacSHA1'  | '65353130'
        seed32  | 20000000000 | 'HmacSHA256'| '77737706'
        seed64  | 20000000000 | 'HmacSHA512'| '47863826'

    }

    private String stepsForTime(unixTime, T0, timeStep) {
        Long T = (unixTime - T0) / timeStep
        String steps = Long.toHexString(T).toUpperCase()
        while (steps.length() < 16) {
            steps = "0" + steps;
        }
        steps
    }

}
