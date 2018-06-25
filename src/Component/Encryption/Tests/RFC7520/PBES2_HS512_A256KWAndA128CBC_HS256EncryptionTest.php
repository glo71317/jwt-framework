<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Encryption\Tests\RFC7520;

use Base64Url\Base64Url;
use Jose\Component\Core\JWK;
use Jose\Component\Encryption\Tests\EncryptionTest;

/**
 * @see https://tools.ietf.org/html/rfc7520#section-5.3
 *
 * @group RFC7520
 */
class PBES2_HS512_A256KWAndA128CBC_HS256EncryptionTest extends EncryptionTest
{
    /**
     * Please note that we cannot the encryption and get the same result as the example (IV, TAG and other data are always different).
     * The output given in the RFC is used and only decrypted.
     */
    public function testPBES2_HS512_A256KWAndA128CBC_HS256Encryption()
    {
        $expected_payload = ['keys' => [
            [
                'kty' => 'oct',
                'kid' => '77c7e2b8-6e13-45cf-8672-617b5b45243a',
                'use' => 'enc',
                'alg' => 'A128GCM',
                'k' => 'XctOhJAkA-pD9Lh7ZgW_2A',
            ], [
                'kty' => 'oct',
                'kid' => '81b20965-8332-43d9-a468-82160ad91ac8',
                'use' => 'enc',
                'alg' => 'A128KW',
                'k' => 'GZy6sIZ6wl9NJOKB-jnmVQ',
            ], [
                'kty' => 'oct',
                'kid' => '18ec08e1-bfa9-4d95-b205-2b4dd1d4321d',
                'use' => 'enc',
                'alg' => 'A256GCMKW',
                'k' => 'qC57l_uxcm7Nm3K-ct4GFjx8tM1U8CZ0NLBvdQstiS8',
            ],
        ]];

        $private_key = JWK::create([
            'kty' => 'oct',
            'use' => 'enc',
            'k' => Base64Url::encode("entrap_o\xe2\x80\x93peter_long\xe2\x80\x93credit_tun"),
        ]);

        $protectedHeader = [
            'alg' => 'PBES2-HS512+A256KW',
            'p2s' => '8Q1SzinasR3xchYz6ZZcHA',
            'p2c' => 8192,
            'cty' => 'jwk-set+json',
            'enc' => 'A128CBC-HS256',
        ];

        $expected_compact_json = 'eyJhbGciOiJQQkVTMi1IUzUxMitBMjU2S1ciLCJwMnMiOiI4UTFTemluYXNSM3hjaFl6NlpaY0hBIiwicDJjIjo4MTkyLCJjdHkiOiJqd2stc2V0K2pzb24iLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.d3qNhUWfqheyPp4H8sjOWsDYajoej4c5Je6rlUtFPWdgtURtmeDV1g.VBiCzVHNoLiR3F4V82uoTQ.23i-Tb1AV4n0WKVSSgcQrdg6GRqsUKxjruHXYsTHAJLZ2nsnGIX86vMXqIi6IRsfywCRFzLxEcZBRnTvG3nhzPk0GDD7FMyXhUHpDjEYCNA_XOmzg8yZR9oyjo6lTF6si4q9FZ2EhzgFQCLO_6h5EVg3vR75_hkBsnuoqoM3dwejXBtIodN84PeqMb6asmas_dpSsz7H10fC5ni9xIz424givB1YLldF6exVmL93R3fOoOJbmk2GBQZL_SEGllv2cQsBgeprARsaQ7Bq99tT80coH8ItBjgV08AtzXFFsx9qKvC982KLKdPQMTlVJKkqtV4Ru5LEVpBZXBnZrtViSOgyg6AiuwaS-rCrcD_ePOGSuxvgtrokAKYPqmXUeRdjFJwafkYEkiuDCV9vWGAi1DH2xTafhJwcmywIyzi4BqRpmdn_N-zl5tuJYyuvKhjKv6ihbsV_k1hJGPGAxJ6wUpmwC4PTQ2izEm0TuSE8oMKdTw8V3kobXZ77ulMwDs4p.0HlwodAhOCILG5SQ2LQ9dg';
        $expected_flattened_json = '{"protected":"eyJhbGciOiJQQkVTMi1IUzUxMitBMjU2S1ciLCJwMnMiOiI4UTFTemluYXNSM3hjaFl6NlpaY0hBIiwicDJjIjo4MTkyLCJjdHkiOiJqd2stc2V0K2pzb24iLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0","encrypted_key":"d3qNhUWfqheyPp4H8sjOWsDYajoej4c5Je6rlUtFPWdgtURtmeDV1g","iv":"VBiCzVHNoLiR3F4V82uoTQ","ciphertext":"23i-Tb1AV4n0WKVSSgcQrdg6GRqsUKxjruHXYsTHAJLZ2nsnGIX86vMXqIi6IRsfywCRFzLxEcZBRnTvG3nhzPk0GDD7FMyXhUHpDjEYCNA_XOmzg8yZR9oyjo6lTF6si4q9FZ2EhzgFQCLO_6h5EVg3vR75_hkBsnuoqoM3dwejXBtIodN84PeqMb6asmas_dpSsz7H10fC5ni9xIz424givB1YLldF6exVmL93R3fOoOJbmk2GBQZL_SEGllv2cQsBgeprARsaQ7Bq99tT80coH8ItBjgV08AtzXFFsx9qKvC982KLKdPQMTlVJKkqtV4Ru5LEVpBZXBnZrtViSOgyg6AiuwaS-rCrcD_ePOGSuxvgtrokAKYPqmXUeRdjFJwafkYEkiuDCV9vWGAi1DH2xTafhJwcmywIyzi4BqRpmdn_N-zl5tuJYyuvKhjKv6ihbsV_k1hJGPGAxJ6wUpmwC4PTQ2izEm0TuSE8oMKdTw8V3kobXZ77ulMwDs4p","tag":"0HlwodAhOCILG5SQ2LQ9dg"}';
        $expected_json = '{"recipients":[{"encrypted_key":"d3qNhUWfqheyPp4H8sjOWsDYajoej4c5Je6rlUtFPWdgtURtmeDV1g"}],"protected":"eyJhbGciOiJQQkVTMi1IUzUxMitBMjU2S1ciLCJwMnMiOiI4UTFTemluYXNSM3hjaFl6NlpaY0hBIiwicDJjIjo4MTkyLCJjdHkiOiJqd2stc2V0K2pzb24iLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0","iv":"VBiCzVHNoLiR3F4V82uoTQ","ciphertext":"23i-Tb1AV4n0WKVSSgcQrdg6GRqsUKxjruHXYsTHAJLZ2nsnGIX86vMXqIi6IRsfywCRFzLxEcZBRnTvG3nhzPk0GDD7FMyXhUHpDjEYCNA_XOmzg8yZR9oyjo6lTF6si4q9FZ2EhzgFQCLO_6h5EVg3vR75_hkBsnuoqoM3dwejXBtIodN84PeqMb6asmas_dpSsz7H10fC5ni9xIz424givB1YLldF6exVmL93R3fOoOJbmk2GBQZL_SEGllv2cQsBgeprARsaQ7Bq99tT80coH8ItBjgV08AtzXFFsx9qKvC982KLKdPQMTlVJKkqtV4Ru5LEVpBZXBnZrtViSOgyg6AiuwaS-rCrcD_ePOGSuxvgtrokAKYPqmXUeRdjFJwafkYEkiuDCV9vWGAi1DH2xTafhJwcmywIyzi4BqRpmdn_N-zl5tuJYyuvKhjKv6ihbsV_k1hJGPGAxJ6wUpmwC4PTQ2izEm0TuSE8oMKdTw8V3kobXZ77ulMwDs4p","tag":"0HlwodAhOCILG5SQ2LQ9dg"}';
        $expected_iv = 'VBiCzVHNoLiR3F4V82uoTQ';
        $expected_encrypted_key = 'd3qNhUWfqheyPp4H8sjOWsDYajoej4c5Je6rlUtFPWdgtURtmeDV1g';
        $expected_ciphertext = '23i-Tb1AV4n0WKVSSgcQrdg6GRqsUKxjruHXYsTHAJLZ2nsnGIX86vMXqIi6IRsfywCRFzLxEcZBRnTvG3nhzPk0GDD7FMyXhUHpDjEYCNA_XOmzg8yZR9oyjo6lTF6si4q9FZ2EhzgFQCLO_6h5EVg3vR75_hkBsnuoqoM3dwejXBtIodN84PeqMb6asmas_dpSsz7H10fC5ni9xIz424givB1YLldF6exVmL93R3fOoOJbmk2GBQZL_SEGllv2cQsBgeprARsaQ7Bq99tT80coH8ItBjgV08AtzXFFsx9qKvC982KLKdPQMTlVJKkqtV4Ru5LEVpBZXBnZrtViSOgyg6AiuwaS-rCrcD_ePOGSuxvgtrokAKYPqmXUeRdjFJwafkYEkiuDCV9vWGAi1DH2xTafhJwcmywIyzi4BqRpmdn_N-zl5tuJYyuvKhjKv6ihbsV_k1hJGPGAxJ6wUpmwC4PTQ2izEm0TuSE8oMKdTw8V3kobXZ77ulMwDs4p';
        $expected_tag = '0HlwodAhOCILG5SQ2LQ9dg';

        $jweDecrypter = $this->getJWEDecrypterFactory()->create(['PBES2-HS512+A256KW'], ['A128CBC-HS256'], ['DEF']);

        $loaded_compact_json = $this->getJWESerializerManager()->unserialize($expected_compact_json);
        self::assertTrue($jweDecrypter->decryptUsingKey($loaded_compact_json, $private_key, 0));

        $loaded_flattened_json = $this->getJWESerializerManager()->unserialize($expected_flattened_json);
        self::assertTrue($jweDecrypter->decryptUsingKey($loaded_flattened_json, $private_key, 0));

        $loaded_json = $this->getJWESerializerManager()->unserialize($expected_json);
        self::assertTrue($jweDecrypter->decryptUsingKey($loaded_json, $private_key, 0));

        self::assertEquals($expected_ciphertext, Base64Url::encode($loaded_compact_json->getCiphertext()));
        self::assertEquals($protectedHeader, $loaded_compact_json->getSharedProtectedHeader());
        self::assertEquals($expected_iv, Base64Url::encode($loaded_compact_json->getIV()));
        self::assertEquals($expected_encrypted_key, Base64Url::encode($loaded_compact_json->getRecipient(0)->getEncryptedKey()));
        self::assertEquals($expected_tag, Base64Url::encode($loaded_compact_json->getTag()));

        self::assertEquals($expected_ciphertext, Base64Url::encode($loaded_flattened_json->getCiphertext()));
        self::assertEquals($protectedHeader, $loaded_flattened_json->getSharedProtectedHeader());
        self::assertEquals($expected_iv, Base64Url::encode($loaded_flattened_json->getIV()));
        self::assertEquals($expected_encrypted_key, Base64Url::encode($loaded_flattened_json->getRecipient(0)->getEncryptedKey()));
        self::assertEquals($expected_tag, Base64Url::encode($loaded_flattened_json->getTag()));

        self::assertEquals($expected_ciphertext, Base64Url::encode($loaded_json->getCiphertext()));
        self::assertEquals($protectedHeader, $loaded_json->getSharedProtectedHeader());
        self::assertEquals($expected_iv, Base64Url::encode($loaded_json->getIV()));
        self::assertEquals($expected_encrypted_key, Base64Url::encode($loaded_json->getRecipient(0)->getEncryptedKey()));
        self::assertEquals($expected_tag, Base64Url::encode($loaded_json->getTag()));

        self::assertEquals($expected_payload, \json_decode($loaded_compact_json->getPayload(), true));
        self::assertEquals($expected_payload, \json_decode($loaded_flattened_json->getPayload(), true));
        self::assertEquals($expected_payload, \json_decode($loaded_json->getPayload(), true));
    }

    /**
     * Same input as before, but we perform the encryption first.
     */
    public function testPBES2_HS512_A256KWAndA128CBC_HS256EncryptionBis()
    {
        $expected_payload = \json_encode(['keys' => [
            [
                'kty' => 'oct',
                'kid' => '77c7e2b8-6e13-45cf-8672-617b5b45243a',
                'use' => 'enc',
                'alg' => 'A128GCM',
                'k' => 'XctOhJAkA-pD9Lh7ZgW_2A',
            ], [
                'kty' => 'oct',
                'kid' => '81b20965-8332-43d9-a468-82160ad91ac8',
                'use' => 'enc',
                'alg' => 'A128KW',
                'k' => 'GZy6sIZ6wl9NJOKB-jnmVQ',
            ], [
                'kty' => 'oct',
                'kid' => '18ec08e1-bfa9-4d95-b205-2b4dd1d4321d',
                'use' => 'enc',
                'alg' => 'A256GCMKW',
                'k' => 'qC57l_uxcm7Nm3K-ct4GFjx8tM1U8CZ0NLBvdQstiS8',
            ],
        ]]);

        $private_key = JWK::create([
            'kty' => 'oct',
            'use' => 'enc',
            'k' => Base64Url::encode("entrap_o\xe2\x80\x93peter_long\xe2\x80\x93credit_tun"),
        ]);

        $protectedHeader = [
            'alg' => 'PBES2-HS512+A256KW',
            'cty' => 'jwk-set+json',
            'enc' => 'A128CBC-HS256',
        ];

        $jweBuilder = $this->getJWEBuilderFactory()->create(['PBES2-HS512+A256KW'], ['A128CBC-HS256'], ['DEF']);
        $jweDecrypter = $this->getJWEDecrypterFactory()->create(['PBES2-HS512+A256KW'], ['A128CBC-HS256'], ['DEF']);

        $jwe = $jweBuilder
            ->create()->withPayload($expected_payload)
            ->withSharedProtectedHeader($protectedHeader)
            ->addRecipient($private_key)
            ->build();

        $loaded_flattened_json = $this->getJWESerializerManager()->unserialize($this->getJWESerializerManager()->serialize('jwe_json_flattened', $jwe, 0));
        self::assertTrue($jweDecrypter->decryptUsingKey($loaded_flattened_json, $private_key, 0));

        $loaded_json = $this->getJWESerializerManager()->unserialize($this->getJWESerializerManager()->serialize('jwe_json_general', $jwe));
        self::assertTrue($jweDecrypter->decryptUsingKey($loaded_json, $private_key, 0));

        self::assertTrue(\array_key_exists('p2s', $loaded_flattened_json->getSharedProtectedHeader()));
        self::assertTrue(\array_key_exists('p2c', $loaded_flattened_json->getSharedProtectedHeader()));

        self::assertTrue(\array_key_exists('p2s', $loaded_json->getSharedProtectedHeader()));
        self::assertTrue(\array_key_exists('p2c', $loaded_json->getSharedProtectedHeader()));

        self::assertEquals($expected_payload, $loaded_flattened_json->getPayload());
        self::assertEquals($expected_payload, $loaded_json->getPayload());
    }
}
