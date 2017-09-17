#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/*
make && /opt/nginx-hello-world/sbin/nginx -s stop && rm -rf /opt/nginx-hello-world && make install && cp /opt/nginx-1.12.1/nginx.conf /opt/nginx-hello-world/conf/nginx.conf && /opt/nginx-hello-world/sbin/nginx
*/

typedef struct
{
    ngx_str_t output_words;
} ngx_http_c_waf_loc_conf_t;

// To process HelloWorld command arguments
static char *ngx_http_c_waf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

// Allocate memory for HelloWorld command
static void *ngx_http_c_waf_create_loc_conf(ngx_conf_t *cf);

// Copy HelloWorld argument to another place
static char *ngx_http_c_waf_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

// Structure for the HelloWorld command
static ngx_command_t ngx_http_c_waf_commands[] = {
    {ngx_string("waf"), // The command name
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_http_c_waf, // The command handler
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_hello_world_loc_conf_t, output_words),
     NULL},
    ngx_null_command};

// Structure for the HelloWorld context
static ngx_http_module_t ngx_http_hello_world_module_ctx = {
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    ngx_http_hello_world_create_loc_conf,
    ngx_http_hello_world_merge_loc_conf};

// Structure for the HelloWorld module, the most important thing
ngx_module_t ngx_http_hello_world_module = {
    NGX_MODULE_V1,
    &ngx_http_hello_world_module_ctx,
    ngx_http_hello_world_commands,
    NGX_HTTP_MODULE,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING};

static void *ngx_http_hello_world_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_hello_world_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_hello_world_loc_conf_t));
    if (conf == NULL)
    {
        return NGX_CONF_ERROR;
    }
    conf->output_words.len = 0;
    conf->output_words.data = NULL;

    return conf;
}

static char *ngx_http_hello_world_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_hello_world_loc_conf_t *prev = parent;
    ngx_http_hello_world_loc_conf_t *conf = child;
    ngx_conf_merge_str_value(conf->output_words, prev->output_words, "Nginx");
    return NGX_CONF_OK;
}

/****************************************************************************** 
 **函数名称: ngx_http_send_rep 
 **功    能: 发送应答数据 
 **输入参数: 
 **     r: Http request. 
 **     repmsg: 应答消息 
 **输出参数: NONE 
 **返    回: 0:Success !0:Failed 
 **实现描述: 
 **    1.发送应答头 
 **    2.发送应答体 
 **注意事项: 
 **作    者: # horan-geeker # 2017.09.17 # 
 ******************************************************************************/
static int ngx_http_send_rep(ngx_http_request_t *r, const ngx_str_t *response)
{
    ngx_int_t ret = 0;
    ngx_buf_t *b = NULL;
    ngx_chain_t out;
    ngx_str_t type = ngx_string("text/plain");

    /* 1.发送应答头 */
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_type = type;
    r->headers_out.content_length_n = response->len;

    ret = ngx_http_send_header(r);
    if ((NGX_ERROR == ret) || (ret > NGX_OK) || (r->header_only))
    {
        return ret;
    }

    /* 2.发送应答体 */
    b = ngx_create_temp_buf(r->pool, response->len);
    if (NULL == b)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_memcpy(b->pos, response->data, response->len);
    b->last = b->pos + response->len;
    b->last_buf = 1;

    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}

/****************************************************************************** 
 **函数名称: ngx_http_black_filter 
 **功    能: 过滤http请求参数
 **输入参数: 
 **     param: HTTP请求. 
 **     dict: 过滤规则. 
 **返    回: NGX_OK:Success !NGX_ERROR0:Failed 
 **实现描述: 
 **    1.检查恶意请求并返回错误 
 **    2.记录日志
 **注意事项: 
 **作    者: # horan-geeker # 2017.09.17 # 
 ******************************************************************************/
static ngx_int_t ngx_http_black_filter(ngx_str_t param, ngx_str_t dict)
{
    if (strcasestr((char*)param.data, (char*)dict.data))
    {
        return NGX_ERROR;
    }
    return NGX_OK;
}

/****************************************************************************** 
 **函数名称: ngx_http_hello_world_handler 
 **功    能: 处理http请求的业务逻辑
 **输入参数: 
 **     r: HTTP请求. 
 **返    回: 0:Success !0:Failed 
 **实现描述: 
 **    1.必须是GET或POST请求 
 **    2.必须是localhost
 **    3.验证URL参数合法性 
 **    4.返回自定义请求头
 **    5.防cc攻击
 **    6.log的ui日志 
 **    7.发送应答数据 
 **注意事项: 
 **作    者: # horan-geeker # 2017.09.17 # 
 ******************************************************************************/
static ngx_int_t ngx_http_hello_world_handler(ngx_http_request_t *r)
{
    ngx_int_t ret = 0, uri_status = 0, param_status = 0;
    ngx_str_t response = ngx_string("Hello World!");
    ngx_str_t dict;
    ngx_http_hello_world_loc_conf_t *hlcf;

    /* 1. 必须是GET或POST请求 */
    if (!(r->method & (NGX_HTTP_GET | NGX_HTTP_POST)))
    {
        return NGX_HTTP_NOT_ALLOWED;
    }

    /* 2. 验证 ip */
    struct sockaddr_in *sin = (struct sockaddr_in *)(r->connection->sockaddr);
    char *ip_str = inet_ntoa(sin->sin_addr);
    if (strncmp(ip_str, "127.0.0.1", strlen(ip_str)) != 0)
    {
        return NGX_HTTP_FORBIDDEN;
    }

    ret = ngx_http_discard_request_body(r); /* 丢弃请求报文体 */
    if (NGX_OK != ret)
    {
        return ret;
    }

    /* 3. 获取配置信息,验证参数 */
    hlcf = ngx_http_get_module_loc_conf(r, ngx_http_hello_world_module);
    dict = hlcf->output_words;
    if (r->uri_start)
    {
        uri_status = ngx_http_black_filter(r->uri, dict);
    }
    if (r->args_start)
    {
        param_status = ngx_http_black_filter(r->args, dict);
    }
    if (uri_status != NGX_OK || param_status != NGX_OK)
    {
        /* 6. log 日志记录恶意请求 */
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s", "detect attact!");
        return NGX_HTTP_FORBIDDEN;
    }

    /* 4. 返回自定义请求头 */
    ngx_str_t custom_header_name = ngx_string("TestHeader");
    ngx_str_t custom_header_value = ngx_string("TestHeaderValue");
    ngx_table_elt_t *h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL)
    {
        return NGX_ERROR;
    }
    h->hash = 1;
    h->key = custom_header_name;
    h->value = custom_header_value;

    /* 5. 防cc */
    
    /* 7. 发送应答数据 */
    return ngx_http_send_rep(r, &response);
}

/****************************************************************************** 
 **函数名称: ngx_http_hello_world 
 **功    能: 配置项 hello_world 的解析处理回调(相当于入口函数) 
 **输入参数: 
 **     cf: 配置信息对象 
 **     cmd: 当前正在解析的配置项解析数组 
 **     conf: 自定义配置结构体ngx_http_login_loc_conf_t的地址 
 **返    回: NGX_CONF_OK:Success Other:Failed 
 **实现描述: 
 **注意事项: 
 **作    者: # horan-geeker # 2017.09.17 # 
 ******************************************************************************/
static char *ngx_http_hello_world(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf;
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_hello_world_handler;
    ngx_conf_set_str_slot(cf, cmd, conf);
    return NGX_CONF_OK;
}