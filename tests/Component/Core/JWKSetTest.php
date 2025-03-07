<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Core;

use InvalidArgumentException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use const JSON_THROW_ON_ERROR;

/**
 * @internal
 */
final class JWKSetTest extends TestCase
{
    #[Test]
    public function iCanSelectAKeyInAKeySet(): void
    {
        $jwkset = $this->getPublicKeySet();

        $jwk = $jwkset->selectKey('enc');
        static::assertInstanceOf(JWK::class, $jwk);
    }

    #[Test]
    public function iCannotSelectAKeyFromAKeySetWithUnsupportedUsageParameter(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Allowed key types are "sig" or "enc".');

        $jwkset = $this->getPublicKeySet();
        $jwkset->selectKey('foo');
    }

    #[Test]
    public function iCannotCreateAKeySetWithBadArguments(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid data.');

        JWKSet::createFromKeyData([
            'keys' => true,
        ]);
    }

    #[Test]
    public function iCanGetAllKeysInAKeySet(): void
    {
        $jwkset = $this->getPublicKeySet();
        static::assertCount(3, $jwkset->all());
    }

    #[Test]
    public function iCanAddKeysInAKeySet(): void
    {
        $jwkset = $this->getPublicKeySet();
        $new_jwkset = $jwkset->with(new JWK([
            'kty' => 'none',
        ]));
        static::assertCount(4, $new_jwkset->all());
        static::assertNotSame($jwkset, $new_jwkset);
    }

    #[Test]
    public function iCanSelectAKeyWithAlgorithm(): void
    {
        $jwkset = $this->getPublicKeySet();

        $jwk = $jwkset->selectKey('enc', new FooAlgorithm());
        static::assertInstanceOf(JWK::class, $jwk);
        static::assertSame([
            'kid' => '71ee230371d19630bc17fb90ccf20ae632ad8cf8',
            'kty' => 'FOO',
            'alg' => 'foo',
            'use' => 'enc',
        ], $jwk->all());
    }

    #[Test]
    public function iCanSelectAKeyWithAlgorithmAndKeyId(): void
    {
        $jwkset = $this->getPublicKeySet();

        $jwk = $jwkset->selectKey('sig', new FooAlgorithm(), [
            'kid' => '02491f945c951adf156f370788e8ccdabf8877a8',
        ]);
        static::assertInstanceOf(JWK::class, $jwk);
        static::assertSame([
            'kid' => '02491f945c951adf156f370788e8ccdabf8877a8',
            'kty' => 'FOO',
            'alg' => 'foo',
            'use' => 'sig',
        ], $jwk->all());
    }

    #[Test]
    public function iCanSelectAKeyWithWithKeyId(): void
    {
        $jwkset = $this->getPublicKeySet();

        $jwk = $jwkset->selectKey('sig', null, [
            'kid' => '02491f945c951adf156f370788e8ccdabf8877a8',
        ]);
        static::assertInstanceOf(JWK::class, $jwk);
        static::assertSame([
            'kid' => '02491f945c951adf156f370788e8ccdabf8877a8',
            'kty' => 'FOO',
            'alg' => 'foo',
            'use' => 'sig',
        ], $jwk->all());
    }

    #[Test]
    public function theKeySetDoesNotContainsSuitableAKeyThatFitsOnTheRequirements(): void
    {
        $jwkset = $this->getPublicKeySet();

        $jwk = $jwkset->selectKey('enc', null, [
            'kid' => '02491f945c951adf156f370788e8ccdabf8877a8',
        ]);
        static::assertNull($jwk);
    }

    #[Test]
    public function iCanCreateAKeySetUsingValues(): void
    {
        $values = [
            'keys' => [[
                'kid' => '71ee230371d19630bc17fb90ccf20ae632ad8cf8',
                'kty' => 'FOO',
                'alg' => 'foo',
                'use' => 'sig',
            ]],
        ];
        $jwkset = JWKSet::createFromKeyData($values);
        static::assertCount(1, $jwkset);
        static::assertTrue($jwkset->has('71ee230371d19630bc17fb90ccf20ae632ad8cf8'));
        static::assertFalse($jwkset->has(0));
    }

    #[Test]
    public function keySet(): void
    {
        $jwk1 = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'use' => 'sign',
            'key_ops' => ['sign'],
            'alg' => 'ES256',
            'kid' => '0123456789',
        ]);

        $jwk2 = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'd' => 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI',
            'use' => 'sign',
            'key_ops' => ['verify'],
            'alg' => 'ES256',
            'kid' => '9876543210',
        ]);

        $jwkset = new JWKSet([$jwk1]);
        $jwkset = $jwkset->with($jwk2);

        static::assertSame(
            '{"keys":[{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","use":"sign","key_ops":["sign"],"alg":"ES256","kid":"0123456789"},{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI","use":"sign","key_ops":["verify"],"alg":"ES256","kid":"9876543210"}]}',
            json_encode($jwkset, JSON_THROW_ON_ERROR)
        );
        static::assertCount(2, $jwkset);
        static::assertCount(2, $jwkset);
        static::assertTrue($jwkset->has('0123456789'));
        static::assertTrue($jwkset->has('9876543210'));
        static::assertFalse($jwkset->has(0));

        foreach ($jwkset as $key) {
            static::assertSame('EC', $key->get('kty'));
        }

        static::assertSame('9876543210', $jwkset->get('9876543210')->get('kid'));
        $jwkset = $jwkset->without('9876543210');
        $jwkset = $jwkset->without('9876543210');

        static::assertCount(1, $jwkset);
        static::assertCount(1, $jwkset);

        $jwkset = $jwkset->without('0123456789');
        static::assertCount(0, $jwkset);
    }

    #[Test]
    public function keySet2(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Undefined index.');

        $jwk1 = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'use' => 'sign',
            'key_ops' => ['sign'],
            'alg' => 'ES256',
            'kid' => '0123456789',
        ]);

        $jwk2 = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'd' => 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI',
            'use' => 'sign',
            'key_ops' => ['verify'],
            'alg' => 'ES256',
            'kid' => '9876543210',
        ]);

        $jwkset = new JWKSet([$jwk1, $jwk2]);

        $jwkset->get(2);
    }

    private function getPublicKeySet(): JWKSet
    {
        $keys = [
            'keys' => [
                [
                    'kid' => '71ee230371d19630bc17fb90ccf20ae632ad8cf8',
                    'kty' => 'FOO',
                    'alg' => 'foo',
                    'use' => 'enc',
                ],
                [
                    'kid' => '02491f945c951adf156f370788e8ccdabf8877a8',
                    'kty' => 'FOO',
                    'alg' => 'foo',
                    'use' => 'sig',
                ],
                [
                    'kty' => 'EC',
                    'crv' => 'P-256',
                    'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
                    'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
                ],
            ],
        ];

        return JWKSet::createFromKeyData($keys);
    }
}
