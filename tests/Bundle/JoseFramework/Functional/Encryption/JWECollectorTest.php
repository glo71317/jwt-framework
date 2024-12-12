<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\Functional\Encryption;

use Jose\Bundle\JoseFramework\DataCollector\JWECollector;
use Jose\Bundle\JoseFramework\Services\JWEBuilderFactory as JWEBuilderFactoryService;
use Jose\Bundle\JoseFramework\Services\JWEDecrypterFactory as JWEDecrypterFactoryService;
use Jose\Bundle\JoseFramework\Services\JWELoaderFactory as JWELoaderFactoryAlias;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * @internal
 */
final class JWECollectorTest extends WebTestCase
{
    #[Test]
    public function aJWEBuilderCanBeCollectedWithoutACompressionMethodManager(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertInstanceOf(ContainerInterface::class, $container);

        $jweFactory = $container->get(JWEBuilderFactoryService::class);
        static::assertInstanceOf(JWEBuilderFactoryService::class, $jweFactory);

        $jweBuilder = $jweFactory->create(['RSA1_5', 'A256GCM']);

        $jweCollector = new JWECollector();
        $jweCollector->addJWEBuilder('builder2', $jweBuilder);

        $data = [];
        $jweCollector->collect($data, new Request(), new Response());

        static::assertArrayHasKey('jwe', $data);
        static::assertArrayNotHasKey('compression_methods', $data['jwe']);
        static::assertArrayHasKey('jwe_builders', $data['jwe']);
        static::assertArrayHasKey('builder2', $data['jwe']['jwe_builders']);
    }

    #[Test]
    public function aJWEDecrypterCanBeCollectedWithoutACompressionMethodManager(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertInstanceOf(ContainerInterface::class, $container);

        $jweDecrypterFactory = $container->get(JWEDecrypterFactoryService::class);
        static::assertInstanceOf(JWEDecrypterFactoryService::class, $jweDecrypterFactory);

        $jweDecrypter = $jweDecrypterFactory->create(['RSA1_5', 'A256GCM']);

        $jweCollector = new JWECollector();
        $jweCollector->addJWEDecrypter('decrypter2', $jweDecrypter);

        $data = [];
        $jweCollector->collect($data, new Request(), new Response());

        static::assertArrayHasKey('jwe', $data);
        static::assertArrayNotHasKey('compression_methods', $data['jwe']);

        static::assertArrayHasKey('jwe_decrypters', $data['jwe']);
        static::assertArrayHasKey('decrypter2', $data['jwe']['jwe_decrypters']);
    }

    #[Test]
    public function aJWELoaderCanBeCollectedWithoutACompressionMethodManager(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertInstanceOf(ContainerInterface::class, $container);

        $jweLoaderFactory = $container->get(JWELoaderFactoryAlias::class);
        static::assertInstanceOf(JWELoaderFactoryAlias::class, $jweLoaderFactory);

        $jweLoader = $jweLoaderFactory->create(['jwe_compact'], ['RSA1_5', 'A256GCM']);

        $jweCollector = new JWECollector();
        $jweCollector->addJWELoader('loader2', $jweLoader);

        $data = [];
        $jweCollector->collect($data, new Request(), new Response());

        static::assertArrayHasKey('jwe', $data);
        static::assertArrayNotHasKey('compression_methods', $data['jwe']);
        static::assertArrayHasKey('jwe_loaders', $data['jwe']);
        static::assertArrayHasKey('loader2', $data['jwe']['jwe_loaders']);
    }
}
