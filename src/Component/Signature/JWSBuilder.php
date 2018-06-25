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

namespace Jose\Component\Signature;

use Base64Url\Base64Url;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\Converter\JsonConverter;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\KeyChecker;
use Jose\Component\Signature\Algorithm\SignatureAlgorithm;

class JWSBuilder
{
    /**
     * @var JsonConverter
     */
    private $jsonConverter;

    /**
     * @var null|string
     */
    private $payload;

    /**
     * @var bool
     */
    private $isPayloadDetached;

    /**
     * @var array
     */
    private $signatures = [];

    /**
     * @var AlgorithmManager
     */
    private $signatureAlgorithmManager;

    /**
     * @var null|bool
     */
    private $isPayloadEncoded = null;

    /**
     * JWSBuilder constructor.
     *
     * @param JsonConverter    $jsonConverter
     * @param AlgorithmManager $signatureAlgorithmManager
     */
    public function __construct(JsonConverter $jsonConverter, AlgorithmManager $signatureAlgorithmManager)
    {
        $this->jsonConverter = $jsonConverter;
        $this->signatureAlgorithmManager = $signatureAlgorithmManager;
    }

    /**
     * Returns the algorithm manager associated to the builder.
     *
     * @return AlgorithmManager
     */
    public function getSignatureAlgorithmManager(): AlgorithmManager
    {
        return $this->signatureAlgorithmManager;
    }

    /**
     * Reset the current data.
     *
     * @return JWSBuilder
     */
    public function create(): self
    {
        $this->payload = null;
        $this->isPayloadDetached = false;
        $this->signatures = [];
        $this->isPayloadEncoded = null;

        return $this;
    }

    /**
     * Set the payload.
     * This method will return a new JWSBuilder object.
     *
     * @param string $payload
     * @param bool   $isPayloadDetached
     *
     * @return JWSBuilder
     */
    public function withPayload(string $payload, bool $isPayloadDetached = false): self
    {
        if (false === \mb_detect_encoding($payload, 'UTF-8', true)) {
            throw new \InvalidArgumentException('The payload must be encoded in UTF-8');
        }
        $clone = clone $this;
        $clone->payload = $payload;
        $clone->isPayloadDetached = $isPayloadDetached;

        return $clone;
    }

    /**
     * Adds the information needed to compute the signature.
     * This method will return a new JWSBuilder object.
     *
     * @param JWK   $signatureKey
     * @param array $protectedHeader
     * @param array $header
     *
     * @return JWSBuilder
     */
    public function addSignature(JWK $signatureKey, array $protectedHeader, array $header = []): self
    {
        $this->checkB64AndCriticalHeader($protectedHeader);
        $isPayloadEncoded = $this->checkIfPayloadIsEncoded($protectedHeader);
        if (null === $this->isPayloadEncoded) {
            $this->isPayloadEncoded = $isPayloadEncoded;
        } elseif ($this->isPayloadEncoded !== $isPayloadEncoded) {
            throw new \InvalidArgumentException('Foreign payload encoding detected.');
        }
        $this->checkDuplicatedHeaderParameters($protectedHeader, $header);
        KeyChecker::checkKeyUsage($signatureKey, 'signature');
        $signatureAlgorithm = $this->findSignatureAlgorithm($signatureKey, $protectedHeader, $header);
        KeyChecker::checkKeyAlgorithm($signatureKey, $signatureAlgorithm->name());
        $clone = clone $this;
        $clone->signatures[] = [
            'signature_algorithm' => $signatureAlgorithm,
            'signature_key' => $signatureKey,
            'protected_header' => $protectedHeader,
            'header' => $header,
        ];

        return $clone;
    }

    /**
     * Computes all signatures and return the expected JWS object.
     *
     * @return JWS
     */
    public function build(): JWS
    {
        if (null === $this->payload) {
            throw new \RuntimeException('The payload is not set.');
        }
        if (0 === \count($this->signatures)) {
            throw new \RuntimeException('At least one signature must be set.');
        }

        $encodedPayload = false === $this->isPayloadEncoded ? $this->payload : Base64Url::encode($this->payload);
        $jws = JWS::create($this->payload, $encodedPayload, $this->isPayloadDetached);
        foreach ($this->signatures as $signature) {
            /** @var SignatureAlgorithm $signatureAlgorithm */
            $signatureAlgorithm = $signature['signature_algorithm'];
            /** @var JWK $signatureKey */
            $signatureKey = $signature['signature_key'];
            /** @var array $protectedHeader */
            $protectedHeader = $signature['protected_header'];
            /** @var array $header */
            $header = $signature['header'];
            $encodedProtectedHeader = empty($protectedHeader) ? null : Base64Url::encode($this->jsonConverter->encode($protectedHeader));
            $input = \sprintf('%s.%s', $encodedProtectedHeader, $encodedPayload);
            $s = $signatureAlgorithm->sign($signatureKey, $input);
            $jws = $jws->addSignature($s, $protectedHeader, $encodedProtectedHeader, $header);
        }

        return $jws;
    }

    /**
     * @param array $protectedHeader
     *
     * @return bool
     */
    private function checkIfPayloadIsEncoded(array $protectedHeader): bool
    {
        return !\array_key_exists('b64', $protectedHeader) || true === $protectedHeader['b64'];
    }

    /**
     * @param array $protectedHeader
     */
    private function checkB64AndCriticalHeader(array $protectedHeader)
    {
        if (!\array_key_exists('b64', $protectedHeader)) {
            return;
        }
        if (!\array_key_exists('crit', $protectedHeader)) {
            throw new \LogicException('The protected header parameter "crit" is mandatory when protected header parameter "b64" is set.');
        }
        if (!\is_array($protectedHeader['crit'])) {
            throw new \LogicException('The protected header parameter "crit" must be an array.');
        }
        if (!\in_array('b64', $protectedHeader['crit'], true)) {
            throw new \LogicException('The protected header parameter "crit" must contain "b64" when protected header parameter "b64" is set.');
        }
    }

    /**
     * @param array $protectedHeader
     * @param array $header
     * @param JWK   $key
     *
     * @return SignatureAlgorithm
     */
    private function findSignatureAlgorithm(JWK $key, array $protectedHeader, array $header): SignatureAlgorithm
    {
        $completeHeader = \array_merge($header, $protectedHeader);
        if (!\array_key_exists('alg', $completeHeader)) {
            throw new \InvalidArgumentException('No "alg" parameter set in the header.');
        }
        if ($key->has('alg') && $key->get('alg') !== $completeHeader['alg']) {
            throw new \InvalidArgumentException(\sprintf('The algorithm "%s" is not allowed with this key.', $completeHeader['alg']));
        }

        $signatureAlgorithm = $this->signatureAlgorithmManager->get($completeHeader['alg']);
        if (!$signatureAlgorithm instanceof SignatureAlgorithm) {
            throw new \InvalidArgumentException(\sprintf('The algorithm "%s" is not supported.', $completeHeader['alg']));
        }

        return $signatureAlgorithm;
    }

    /**
     * @param array $header1
     * @param array $header2
     */
    private function checkDuplicatedHeaderParameters(array $header1, array $header2)
    {
        $inter = \array_intersect_key($header1, $header2);
        if (!empty($inter)) {
            throw new \InvalidArgumentException(\sprintf('The header contains duplicated entries: %s.', \implode(', ', \array_keys($inter))));
        }
    }
}
