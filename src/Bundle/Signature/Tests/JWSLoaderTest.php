<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Bundle\Signature\Tests;

use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\JWSVerifierFactory;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

/**
 * @group Bundle
 * @group Functional
 */
final class JWSVerifierTest extends WebTestCase
{
    public function testJWSVerifierFactoryIsAvailable()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        self::assertNotNull($container);
        self::assertTrue($container->has(JWSVerifierFactory::class));
    }

    public function testJWSVerifierFactoryCanCreateAJWSVerifier()
    {
        $client = static::createClient();

        /** @var JWSVerifierFactory $jwsFactory */
        $jwsFactory = $client->getContainer()->get(JWSVerifierFactory::class);

        $jws = $jwsFactory->create(['none'], [], ['jws_compact', 'jws_json_general', 'jws_json_flattened']);

        self::assertInstanceOf(JWSVerifier::class, $jws);
    }

    public function testJWSVerifierFromConfigurationIsAvailable()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        self::assertTrue($container->has('jose.jws_verifier.loader1'));

        $jws = $container->get('jose.jws_verifier.loader1');
        self::assertInstanceOf(JWSVerifier::class, $jws);
    }

    public function testJWSVerifierFromExternalBundleExtensionIsAvailable()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        self::assertTrue($container->has('jose.jws_verifier.loader2'));

        $jws = $container->get('jose.jws_verifier.loader2');
        self::assertInstanceOf(JWSVerifier::class, $jws);
    }
}
