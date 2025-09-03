package com.hospital.config;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.orm.jpa.vendor.HibernateJpaVendorAdapter;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.EnableTransactionManagement;

import javax.sql.DataSource;
import jakarta.persistence.EntityManagerFactory;
import java.util.Properties;

/**
 * Database Configuration
 * Implements secure database connection and transaction management
 * Protects against A02: Cryptographic Failures and A03: Injection
 */
@Configuration
@EnableTransactionManagement
@EnableJpaRepositories(
    basePackages = "com.hospital.repository",
    entityManagerFactoryRef = "entityManagerFactory",
    transactionManagerRef = "transactionManager"
)
public class DatabaseConfig {

    @Value("${spring.datasource.url}")
    private String jdbcUrl;

    @Value("${spring.datasource.username}")
    private String username;

    @Value("${spring.datasource.password}")
    private String password;

    @Value("${spring.datasource.driver-class-name}")
    private String driverClassName;

    @Value("${spring.datasource.hikari.maximum-pool-size:20}")
    private int maxPoolSize;

    @Value("${spring.datasource.hikari.minimum-idle:5}")
    private int minIdle;

    @Value("${spring.datasource.hikari.connection-timeout:30000}")
    private long connectionTimeout;

    @Value("${spring.datasource.hikari.idle-timeout:300000}")
    private long idleTimeout;

    @Value("${spring.datasource.hikari.max-lifetime:900000}")
    private long maxLifetime;

    @Value("${spring.datasource.hikari.leak-detection-threshold:60000}")
    private long leakDetectionThreshold;

    /**
     * Primary DataSource with HikariCP connection pooling
     */
    @Bean
    @Primary
    public DataSource dataSource() {
        HikariConfig config = new HikariConfig();
        
        // Basic connection settings
        config.setJdbcUrl(jdbcUrl);
        config.setUsername(username);
        config.setPassword(password);
        config.setDriverClassName(driverClassName);
        
        // Pool configuration
        config.setMaximumPoolSize(maxPoolSize);
        config.setMinimumIdle(minIdle);
        config.setConnectionTimeout(connectionTimeout);
        config.setIdleTimeout(idleTimeout);
        config.setMaxLifetime(maxLifetime);
        config.setLeakDetectionThreshold(leakDetectionThreshold);
        
        // Connection validation
        config.setConnectionTestQuery("SELECT 1");
        config.setValidationTimeout(5000);
        
        // Performance settings
        config.setAutoCommit(false);
        config.setTransactionIsolation("TRANSACTION_READ_COMMITTED");
        config.setPoolName("HealthcareConnectionPool");
        
        // Security settings
        config.addDataSourceProperty("stringtype", "unspecified");
        config.addDataSourceProperty("ApplicationName", "HealthcareAPI");
        config.addDataSourceProperty("ssl", "true");
        config.addDataSourceProperty("sslmode", "require");
        
        // Prepared statement cache
        config.addDataSourceProperty("preparedStatementCacheQueries", "250");
        config.addDataSourceProperty("preparedStatementCacheSizeMiB", "5");
        
        // Additional PostgreSQL-specific settings
        config.addDataSourceProperty("tcpKeepAlive", "true");
        config.addDataSourceProperty("socketTimeout", "30");
        config.addDataSourceProperty("loginTimeout", "10");
        
        return new HikariDataSource(config);
    }

    /**
     * EntityManagerFactory configuration
     */
    @Bean
    public LocalContainerEntityManagerFactoryBean entityManagerFactory() {
        LocalContainerEntityManagerFactoryBean em = new LocalContainerEntityManagerFactoryBean();
        em.setDataSource(dataSource());
        em.setPackagesToScan("com.hospital.entity");
        
        HibernateJpaVendorAdapter vendorAdapter = new HibernateJpaVendorAdapter();
        vendorAdapter.setGenerateDdl(false);
        vendorAdapter.setShowSql(false);
        em.setJpaVendorAdapter(vendorAdapter);
        
        // Hibernate properties
        Properties props = new Properties();
        props.setProperty("hibernate.dialect", "org.hibernate.dialect.PostgreSQLDialect");
        props.setProperty("hibernate.hbm2ddl.auto", "validate");
        props.setProperty("hibernate.format_sql", "false");
        props.setProperty("hibernate.show_sql", "false");
        props.setProperty("hibernate.jdbc.time_zone", "UTC");
        props.setProperty("hibernate.jdbc.batch_size", "50");
        props.setProperty("hibernate.order_inserts", "true");
        props.setProperty("hibernate.order_updates", "true");
        props.setProperty("hibernate.batch_versioned_data", "true");
        props.setProperty("hibernate.connection.provider_disables_autocommit", "true");
        
        // Second-level cache (if using)
        props.setProperty("hibernate.cache.use_second_level_cache", "false");
        props.setProperty("hibernate.cache.use_query_cache", "false");
        
        // Statistics (disable in production)
        props.setProperty("hibernate.generate_statistics", "false");
        
        em.setJpaProperties(props);
        return em;
    }

    /**
     * Transaction manager
     */
    @Bean
    public PlatformTransactionManager transactionManager(EntityManagerFactory entityManagerFactory) {
        JpaTransactionManager transactionManager = new JpaTransactionManager();
        transactionManager.setEntityManagerFactory(entityManagerFactory);
        transactionManager.setRollbackOnCommitFailure(true);
        return transactionManager;
    }

    /**
     * Development-specific DataSource (H2 in-memory for testing)
     */
    @Bean
    @Profile("test")
    public DataSource testDataSource() {
        HikariConfig config = new HikariConfig();
        config.setJdbcUrl("jdbc:h2:mem:testdb;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE");
        config.setUsername("sa");
        config.setPassword("");
        config.setDriverClassName("org.h2.Driver");
        config.setMaximumPoolSize(5);
        config.setMinimumIdle(2);
        config.setConnectionTimeout(10000);
        config.setAutoCommit(false);
        config.setPoolName("TestConnectionPool");
        
        return new HikariDataSource(config);
    }

    /**
     * Read-only DataSource for reporting (if needed)
     */
    @Bean
    @Profile("!test")
    public DataSource readOnlyDataSource() {
        HikariConfig config = new HikariConfig();
        
        // Use same connection details but mark as read-only
        config.setJdbcUrl(jdbcUrl + "&readOnly=true");
        config.setUsername(username);
        config.setPassword(password);
        config.setDriverClassName(driverClassName);
        
        // Smaller pool for read-only operations
        config.setMaximumPoolSize(maxPoolSize / 2);
        config.setMinimumIdle(2);
        config.setConnectionTimeout(connectionTimeout);
        config.setIdleTimeout(idleTimeout);
        config.setMaxLifetime(maxLifetime);
        
        config.setReadOnly(true);
        config.setPoolName("ReadOnlyConnectionPool");
        
        return new HikariDataSource(config);
    }
}