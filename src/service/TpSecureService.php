<?php
namespace TpSecure\service;

use think\Service;

class TpSecureService extends Service
{
    public function register()
    {
        // 注册可发布配置
        $this->app->config->set('tpsecure', include __DIR__ . '/../../config/tpsecure.php');
    }
}
