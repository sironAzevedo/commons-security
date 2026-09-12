package com.br.azevedo.security;

import org.springframework.web.bind.annotation.RequestMethod;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Anotação centralizadora de segurança e autorização da aplicação.
 *
 * <p>Esta anotação pode ser utilizada em dois cenários principais:</p>
 * <ul>
 *   <li><b>Cenário Global (Classe Principal/Configuração):</b> Quando aplicada à classe principal
 *   da aplicação (ex: {@code @SpringBootApplication}) ou em uma classe de configuração Spring,
 *   ativa a validação de autorização para todos os endpoints da aplicação.</li>
 *   <li><b>Cenário por Método (Controller/HandlerMethod):</b> Quando aplicada diretamente sobre um
 *   método ou controller específico, ativa a validação de autorização somente para aquele endpoint,
 *   mantendo os demais endpoints da aplicação com seu comportamento aberto/existente.</li>
 * </ul>
 *
 * <p><b>Configuração de Métodos/Caminhos Públicos:</b></p>
 * <ul>
 *   <li>{@link #publicPaths()}: Permite especificar padrões de URL (antPath ou regex) que serão
 *   considerados públicos e isentos de validação de token/autorização.</li>
 *   <li>{@link #publicMethods()}: Permite especificar métodos HTTP (ex: {@link RequestMethod#GET})
 *   que serão considerados públicos para os escopos anotados.</li>
 * </ul>
 *
 * <p><b>Regra de Precedência:</b></p>
 * <ol>
 *   <li>Se a URL corresponder a um endpoint público padrão do sistema (via {@code isPublicUrl()}) ou às
 *   configurações explícitas de {@code publicPaths} / {@code publicMethods}, o acesso é PERMITIDO sem autorização.</li>
 *   <li>Se a segurança global estiver ativa (anotação na aplicação/configuração global), endpoints não públicos
 *   exigem autorização.</li>
 *   <li>Se a segurança global NÃO estiver ativa, apenas endpoints/métodos anotados com {@code @EnableSecurity}
 *   exigem autorização.</li>
 * </ol>
 *
 * @author Azevedo Security
 * @since 1.0
 */
@Documented
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
public @interface EnableSecurity {

    /**
     * Define padrões de caminhos/URLs que devem ser tratados como públicos (isento de autorização).
     *
     * @return array de padrões de URL públicas.
     */
    String[] publicPaths() default {};

    /**
     * Define métodos HTTP que devem ser tratados como públicos para o escopo da anotação.
     *
     * @return array de {@link RequestMethod} públicos.
     */
    RequestMethod[] publicMethods() default {};
}

