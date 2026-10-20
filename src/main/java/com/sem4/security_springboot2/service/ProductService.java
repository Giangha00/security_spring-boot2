package com.sem4.security_springboot2.service;

import com.sem4.security_springboot2.dto.ProductRequest;
import com.sem4.security_springboot2.dto.ProductResponse;
import com.sem4.security_springboot2.entity.Product;
import com.sem4.security_springboot2.exception.ResourceNotFoundException;
import com.sem4.security_springboot2.repository.ProductRepository;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@Transactional(readOnly = true)
public class ProductService {
    private final ProductRepository productRepository;

    public ProductService(ProductRepository productRepository) {
        this.productRepository = productRepository;
    }

    public List<ProductResponse> findAll() {
        return productRepository.findAll().stream()
            .map(this::toResponse)
            .toList();
    }

    public ProductResponse findById(Long id) {
        return productRepository.findById(id)
            .map(this::toResponse)
            .orElseThrow(() -> new ResourceNotFoundException("Sản phẩm không tồn tại với id: " + id));
    }

    @PreAuthorize("hasAuthority('SCOPE_product:write')")
    @Transactional
    public ProductResponse create(ProductRequest request) {
        Product product = new Product(request.name(), request.description(), request.price());
        Product saved = productRepository.save(product);
        return toResponse(saved);
    }

    @PreAuthorize("hasAuthority('SCOPE_product:write')")
    @Transactional
    public ProductResponse update(Long id, ProductRequest request) {
        Product product = productRepository.findById(id)
            .orElseThrow(() -> new ResourceNotFoundException("Sản phẩm không tồn tại với id: " + id));

        product.setName(request.name());
        product.setDescription(request.description());
        product.setPrice(request.price());
        Product saved = productRepository.save(product);
        return toResponse(saved);
    }

    @PreAuthorize("hasAuthority('SCOPE_product:write')")
    @Transactional
    public void delete(Long id) {
        if (!productRepository.existsById(id)) {
            throw new ResourceNotFoundException("Sản phẩm không tồn tại với id: " + id);
        }
        productRepository.deleteById(id);
    }

    private ProductResponse toResponse(Product p) {
        return new ProductResponse(
            p.getId(),
            p.getName(),
            p.getDescription(),
            p.getPrice(),
            p.getCreatedAt(),
            p.getUpdatedAt()
        );
    }
}
