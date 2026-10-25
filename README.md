# commons-security

Biblioteca corporativa de autenticação, autorização e segurança para aplicações Spring Boot 3.

---

## Sumário

- [Visão Geral](#visão-geral)
- [@EnableSecurity](#enablesecurity)
  - [Integração com AWS SSM Parameter Store](#integração-com-aws-ssm-parameter-store)
  - [Convenção de Paths e Perfis](#convenção-de-paths-e-perfis)
  - [Reaproveitamento de Conexão AWS](#reaproveitamento-de-conexão-aws)
- [@EnableVault](#enablevault)
  - [Uso Independente do HashiCorp Vault](#uso-independente-do-hashicorp-vault)
  - [Propriedades do Vault](#propriedades-do-vault)
- [@EnableCrypto / @EnableCriptografia](#enablecrypto--enablecriptografia)
  - [Visão e Recursos de Criptografia](#visão-e-recursos-de-criptografia)
  - [Exemplo de Uso](#exemplo-de-uso-da-criptografia)
  - [Propriedades Configuráveis](#propriedades-de-criptografia)
- [Exemplos de Configuração](#exemplos-de-configuração)
  - [Cenário 1: Apenas Segurança (SSM Parameter Store)](#cenário-1-apenas-segurança-ssm-parameter-store)
  - [Cenário 2: Segurança + Vault Independente](#cenário-2-segurança--vault-independente)
  - [Cenário 3: Aplicação Cliente com @EnableAws pré-existente](#cenário-3-aplicação-cliente-com-enableaws-pré-existente)

---

## Visão Geral

A biblioteca `commons-security` fornece:
1. Interceptação de requisições HTTP para validação de cabeçalhos de autorização (`Authorization`) e transação (`transactionid`).
2. Validação de tokens JWT através de chaves públicas/segredos armazenados no **AWS Systems Manager (SSM) Parameter Store**.
3. Suporte opcional e desacoplado ao **HashiCorp Vault** via anotação `@EnableVault`.

---

## @EnableSecurity

Para habilitar a segurança em sua aplicação Spring Boot, adicione a anotação na classe principal:

```java
@SpringBootApplication
@EnableSecurity
public class MinhaAplicacaoApplication {
    public static void main(String[] args) {
        SpringApplication.run(MinhaAplicacaoApplication.class, args);
    }
}
```

### Integração com AWS SSM Parameter Store

A partir desta versão, o Vault **não** é mais dependência obrigatória para buscar as credenciais de validação de token JWT. A busca de chaves/segredos JWT é feita via AWS SSM Parameter Store gerenciada pela biblioteca `azevedo-commons-utils`.

### Convenção de Paths e Perfis

O path padrão utilizado para obter o segredo JWT no Parameter Store é:

```text
/auth-api/jwt/credentials-{ambiente}
```

- **Resolução do `{ambiente}`**:
  1. Propriedade explícita `ambiente` ou `AMBIENTE` (ex: `ambiente: hml`).
  2. Caso não informada, lê o primeiro perfil ativo em `spring.profiles.active` ou variável de ambiente `SPRING_PROFILES_ACTIVE`.
  3. Caso nenhum esteja definido, assume o valor padrão `"dev"` (`/auth-api/jwt/credentials-dev`).

- **Formato da chave**:
  - Se o valor do parâmetro for um JSON contendo o campo `"API_SECRET"`, o valor desse campo será extraído e utilizado.
  - Se for uma string direta, ela será utilizada integralmente como o secret do token.

### Reaproveitamento de Conexão AWS

Ao habilitar `@EnableSecurity`, o Spring Context verifica se:
1. A aplicação cliente já declarou um bean `AwsParameterStoreService` ou `SsmClient` (por exemplo, se já usou `@EnableAws`).
2. Se existir, a conexão é **reaproveitada**.
3. Se não existir, a própria biblioteca `commons-security` inicializa o `SsmClient` e `AwsParameterStoreService` via `commons-utils`, utilizando as credenciais AWS configuradas nas propriedades da aplicação.

---

## @EnableVault

O suporte ao HashiCorp Vault é mantido na aplicação de forma **100% independente**. Nenhuma rotina interna de segurança ou interceptor depende do Vault para iniciar.

Para usar o Vault em sua aplicação:

```java
@SpringBootApplication
@EnableVault
public class MinhaAplicacaoApplication {
    public static void main(String[] args) {
        SpringApplication.run(MinhaAplicacaoApplication.class, args);
    }
}
```

Ao habilitar `@EnableVault`, os seguintes beans são disponibilizados no contexto:
- `VaultParameter`: Configurações de conexão (host, porta, token, scheme).
- `VaultSecretManager`: Gerenciador com métodos para buscar credenciais e segredos no servidor Vault.

### Propriedades do Vault

```yaml
vault:
  host: localhost
  port: 8200
  scheme: http
  token: s.my-vault-token
```

---

## Exemplos de Configuração

### Cenário 1: Apenas Segurança (SSM Parameter Store)

```yaml
spring:
  profiles:
    active: dev

cloud:
  aws:
    region:
      static: us-east-1
    credentials:
      access-key: ${AWS_ACCESS_KEY_ID:}
      secret-key: ${AWS_SECRET_ACCESS_KEY:}

security:
  token:
    secret-name: auth
```

### Cenário 2: Segurança + Vault Independente

```java
@SpringBootApplication
@EnableSecurity
@EnableVault
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}
```

```yaml
vault:
  host: vault.empresa.com.br
  port: 8200
  scheme: https
  token: ${VAULT_TOKEN}

cloud:
  aws:
    region:
      static: us-east-1
    services: ssm
```

### Cenário 3: Aplicação Cliente com @EnableAws pré-existente

Se a sua aplicação já utiliza `@EnableAws`:

```java
@SpringBootApplication
@EnableAws
@EnableSecurity
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}
```

```yaml
cloud:
  aws:
    region:
      static: us-east-1
    services: s3, ssm, sqs
```

Neste caso, o `SsmClient` e `AwsParameterStoreService` criados pelo `@EnableAws` são automaticamente compartilhados com o `@EnableSecurity`, sem duplicação de conexões ou clientes.

---

## @EnableCrypto / @EnableCriptografia

Habilita o serviço centralizado de criptografia simétrica (AES-256-CBC) gerenciada, permitindo criptografar e descriptografar dados sensíveis (senhas, documentos, tokens) de forma segura e padronizada entre os microsserviços.

### Visão e Recursos de Criptografia

- **Chave Mestre Centralizada:** A chave de cifra é recuperada automaticamente do AWS SSM Parameter Store no caminho configurável `/app/data/security/cripto-{environment}`.
- **Cache Inteligente:** A chave é armazenada em cache (TTL padrão de 7 dias) via Redis/local para máxima performance e custo reduzido na AWS.
- **Resolução Automática de Ambiente:** Utiliza `EnvironmentUtils` para determinar o profile ativo (`dev`, `hml`, `prd`, etc.).
- **Desacoplamento e Injeção:** Disponibiliza as interfaces `ICriptografiaService` e `ICryptoService` prontas para injeção via Spring `@Autowired`.
- **Criptografia com Chave Customizada:** Além da chave mestre, suporta `encrypt(texto, chave)` e `decrypt(cifrado, chave)`.

### Exemplo de Uso da Criptografia

```java
@SpringBootApplication
@EnableCrypto // ou @EnableCriptografia
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}
```

Injetando no seu serviço:

```java
@Service
@RequiredArgsConstructor
public class MeuServico {

    private final ICriptografiaService criptografiaService;

    public void salvarSenha(String senhaPlana) {
        String senhaCriptografada = criptografiaService.encrypt(senhaPlana);
        // salva senha criptografada na base
    }

    public String obterSenha(String senhaCriptografada) {
        return criptografiaService.decrypt(senhaCriptografada);
    }
}
```

### Propriedades de Criptografia

Configurações opcionais no `application.yml`:

```yaml
security:
  crypto:
    parameter-path-pattern: "/app/data/security/cripto-%s" # caminho da chave no SSM
    cache-ttl: 7d                                        # TTL do cache da chave mestre
    algorithm: "AES/CBC/PKCS5Padding"                    # algoritmo de cifra
    iv-length-bytes: 16                                   # tamanho do vetor IV
```
