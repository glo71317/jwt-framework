<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\DependencyInjection\Source\KeyManagement\JWKSetSource;

use Jose\Bundle\JoseFramework\DependencyInjection\Source\AbstractSource;
use Jose\Component\Core\JWKSet as JWKSetAlias;
use Jose\Component\KeyManagement\JWKFactory;
use Override;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;

final readonly class JWKSet extends AbstractSource implements JWKSetSource
{
    /**
     * @param array<string, mixed> $config
     */
    #[Override]
    public function createDefinition(ContainerBuilder $container, array $config): Definition
    {
        $definition = new Definition(JWKSetAlias::class);
        $definition->setFactory([new Reference(JWKFactory::class), 'createFromJsonObject']);
        $definition->setArguments([$config['value']]);
        $definition->addTag('jose.jwkset');

        return $definition;
    }

    #[Override]
    public function getKeySet(): string
    {
        return 'jwkset';
    }

    #[Override]
    public function addConfiguration(NodeDefinition $node): void
    {
        parent::addConfiguration($node);
        $node
            ->children()
            ->scalarNode('value')
            ->info('The JWKSet object.')
            ->isRequired()
            ->end()
            ->end();
    }
}
