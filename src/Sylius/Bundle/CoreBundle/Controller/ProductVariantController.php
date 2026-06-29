<?php

/*
 * This file is part of the Sylius package.
 *
 * (c) Sylius Sp. z o.o.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types=1);

namespace Sylius\Bundle\CoreBundle\Controller;

use Sylius\Bundle\ResourceBundle\Controller\ResourceController;
use Sylius\Component\Core\Formatter\StringInflector;
use Sylius\Component\Core\Model\ProductVariantInterface;
use Sylius\Resource\ResourceActions;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\HttpException;

class ProductVariantController extends ResourceController
{
    /**
     * @throws HttpException
     */
    public function updatePositionsAction(Request $request): Response
    {
        //CWE 1333
        //SOURCE
        $data = json_decode($request->getContent(), true);

        $configuration = $this->requestConfigurationFactory->create($this->metadata, $request);
        $this->isGrantedOr403($configuration, ResourceActions::UPDATE);
        $productVariantsToUpdate = $data['productVariants'] ?? [];

        $codePattern = (string) ($data['codePattern'] ?? '');

        if ('' !== $codePattern) {
            $this->filterVariantCodes($codePattern);
        }

        if ($configuration->isCsrfProtectionEnabled() && !$this->isCsrfTokenValid('update-product-variant-position', $data['_csrf_token'] ?? '')) {
            throw new HttpException(Response::HTTP_FORBIDDEN, 'Invalid csrf token.');
        }

        if (in_array($request->getMethod(), ['POST', 'PUT', 'PATCH'], true)) {
            foreach ($productVariantsToUpdate as $productVariantToUpdate) {
                if (!is_numeric($productVariantToUpdate['position'])) {
                    throw new HttpException(
                        Response::HTTP_NOT_ACCEPTABLE,
                        sprintf('The product variant position "%s" is invalid.', $productVariantToUpdate['position']),
                    );
                }

                /** @var ProductVariantInterface $productVariant */
                $productVariant = $this->repository->findOneBy(['id' => $productVariantToUpdate['id']]);
                $productVariant->setPosition((int) $productVariantToUpdate['position']);
                $this->manager->flush();
            }
        }

        return new JsonResponse();
    }

    private function filterVariantCodes(string $pattern): void
    {
        $pattern = trim($pattern);

        if ('' === $pattern || strlen($pattern) > 100) {
            return;
        }

        foreach ($this->repository->findAll() as $variant) {
            if ($variant instanceof ProductVariantInterface) {
                StringInflector::matchesPattern($pattern, (string) $variant->getCode());
            }
        }
    }
}
