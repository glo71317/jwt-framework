<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\DependencyInjection\Source\KeyManagement;

use InvalidArgumentException;
use Jose\Bundle\JoseFramework\DependencyInjection\Source\KeyManagement\JWKSetSource\JWKSetSource as JWKSetSourceInterface;
use Jose\Bundle\JoseFramework\DependencyInjection\Source\Source;
use LogicException;
use Override;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\PhpFileLoader;
use function array_key_exists;
use function count;
use function sprintf;

final class JWKSetSource implements Source
{
    /**
     * @var JWKSetSourceInterface[]
     */
    private ?array $jwkset_sources = null;

    #[Override]
    public function name(): string
    {
        return 'key_sets';
    }

    #[Override]
    public function load(array $configs, ContainerBuilder $container): void
    {
        $sources = $this->getJWKSetSources();
        foreach ($configs[$this->name()] as $name => $itemConfig) {
            foreach ($itemConfig as $sourceName => $sourceConfig) {
                if (array_key_exists($sourceName, $sources)) {
                    $source = $sources[$sourceName];
                    $source->create($container, 'key_set', $name, $sourceConfig);
                } else {
                    throw new LogicException(sprintf('The JWKSet definition "%s" is not configured.', $name));
                }
            }
        }
    }

    #[Override]
    public function getNodeDefinition(NodeDefinition $node): void
    {
        $sourceNodeBuilder = $node
            ->children()
            ->arrayNode('key_sets')
            ->treatFalseLike([])
            ->treatNullLike([])
            ->useAttributeAsKey('name')
            ->arrayPrototype()
            ->validate()
            ->ifTrue(fn ($config): bool => count($config) !== 1)
            ->thenInvalid('One key set type must be set.')
            ->end()
            ->children();
        foreach ($this->getJWKSetSources() as $name => $source) {
            $sourceNode = $sourceNodeBuilder->arrayNode($name)
                ->canBeUnset();
            $source->addConfiguration($sourceNode);
        }
    }

    #[Override]
    public function prepend(ContainerBuilder $container, array $config): array
    {
        return [];
    }

    /**
     * @return JWKSetSourceInterface[]
     */
    private function getJWKSetSources(): array
    {
        if ($this->jwkset_sources !== null) {
            return $this->jwkset_sources;
        }

        // load bundled adapter factories
        $tempContainer = new ContainerBuilder();
        $tempContainer->registerForAutoconfiguration(JWKSetSourceInterface::class)->addTag('jose.jwkset_source');
        $loader = new PhpFileLoader($tempContainer, new FileLocator(__DIR__ . '/../../../Resources/config'));
        $loader->load('jwkset_sources.php');
        $tempContainer->compile(true);

        $services = $tempContainer->findTaggedServiceIds('jose.jwkset_source');
        $jwkset_sources = [];
        foreach (array_keys($services) as $id) {
            $factory = $tempContainer->get($id);
            if (! $factory instanceof JWKSetSourceInterface) {
                throw new InvalidArgumentException('Invalid object');
            }
            $jwkset_sources[str_replace('-', '_', $factory->getKeySet())] = $factory;
        }

        return $this->jwkset_sources = $jwkset_sources;
    }
}
