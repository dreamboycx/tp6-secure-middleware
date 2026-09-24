<?php
/**
 * TpSecure 安全中间件配置
 */
return [
    // SQL注入检测中间件
    'sql_inject' => [
        'enable' => true,
        'sensitive_words' => [],//过滤敏感词
    ],
    // IP黑名单中间件
    'ip_limit' => [
        'enable' => false,
        'black_ip' => [
            // '123.123.123.123'
        ]
    ],
    // API签名中间件
    'api_sign' => [
        'enable' => false,
        'secret' => '',
    ]
];