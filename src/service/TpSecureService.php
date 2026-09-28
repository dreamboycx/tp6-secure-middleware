<?php
namespace TpSecure\service;

use think\Service;

class TpSecureService extends Service
{
    public function register()
    {
        // 已有配置(用户已发布/自定义)则跳过，避免覆盖用户配置
        if (!$this->app->config->has('tpsecure')) {
            $this->app->config->set(include __DIR__ . '/../../config/tpsecure.php', 'tpsecure');
        }
    }
}
