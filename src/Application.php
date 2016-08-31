<?php
/**
 * Created by PhpStorm.
 * User: nazarenko
 * Date: 20.10.2014
 * Time: 11:43
 */
namespace samsoncms\app\signin;

use samson\activerecord\dbQuery;
use samson\cms\CMS;
use samson\social\email\EmailStatus;
use samson\url\URL;
use samsoncms\api\generated\UserQuery;
use samsonframework\containerannotation\InjectArgument;
use samsonframework\core\RequestInterface;
use samsonframework\core\ResourcesInterface;
use samsonframework\core\SystemInterface;
use samsonphp\event\Event;
use samsonframework\orm\QueryInterface;
use samson\social\email\Email;
use samson\core\Core;
use samsonphp\compressor\Compressor;

/**
 * Generic class for user sign in
 * @author Olexandr Nazarenko <nazarenko@samsonos.com>
 * @copyright 2014 SamsonOS
 */
class Application extends \samson\core\CompressableExternalModule
{
    /** @var string Identifier */
    public $id = 'signin';

    /** @var Email Pointer to social email module */
    protected $social;

    /** @var QueryInterface Database query instance */
    protected $query;

    /** @var RequestInterface Request instance */
    protected $request;

    public function authorize($cms)
    {
        if ($cms->isCMS()) {
            if (!$this->social->authorized()) {
                if (!$this->social->cookieVerification()) {
                    if (!$this->request->is('signin')) {
                        $this->request->redirect('/' . $cms->baseUrl . '/signin');
                    }
                } else {
                    $this->request->redirect('/' . $cms->baseUrl . '/signin');
                }
            } else {
                if ($this->request->is('signin')) {
                    $this->request->redirect('/' . $cms->baseUrl);
                }
            }
        }
    }

    public function init(array $params = array())
    {
        $this->request = url();
        // Old applications main page rendering
        Event::subscribe(\samsoncms\cms\Application::EVENT_IS_CMS, array($this, 'authorize'));
        
        Event::subscribe(Compressor::E_CREATE_MODULE_LIST, array($this, 'getModuleList'));

        // Call parent initialization
        return parent::init($params);
    }
    
    public function getModuleList(& $moduleListArray)
    {
        $moduleList = array();
        foreach ($this->system->module_stack as $id => $module) {
            if (isset($module->composerParameters['composerName'])) {
                if (in_array($module->composerParameters['composerName'], $this->composerParameters['required'])) {
                    $moduleList[$id] = $module;
                }
            }
        }
        $moduleList[$this->id] = $this;
        $moduleListArray[$this->path().'www/signin/signin_template.vphp'] = $moduleList;
    }

    /**
     * Application constructor.
     *
     * @param string $path
     * @param ResourcesInterface $resources
     * @param SystemInterface $system
     *
     * @InjectArgument(socialEmail="\samson\social\email\Email")
     * @InjectArgument(request="\samson\url\URL")
     * @InjectArgument(queryInterface="\samsonframework\orm\QueryInterface")
     *
     * @InjectArgument(resources="\samsonframework\core\ResourcesInterface")
     * @InjectArgument(system="\samsonframework\core\SystemInterface")
     */
    public function __construct(Email $socialEmail, URL $request, QueryInterface $queryInterface, ResourcesInterface $resources, SystemInterface $system)
    {
        parent::__construct(realpath(__DIR__ . '/../'), $resources, $system);

        // Inject dependencies
//        $this->social = $this->system->module('socialemail');
//        $this->request = $this->system->module('samsonos_php_url');
//        $this->query = new dbQuery();
        $this->social = $socialEmail;
        $this->request = $request;
        $this->query = $queryInterface;
    }

    //[PHPCOMPRESSOR(remove,start)]
    /** Module preparation */
    public function prepare()
    {
        // Create default user for first logins
        $adminUser = 'admin@admin.com';
        $hashedEmailValue = $this->social->hash($adminUser);

        /** @var \samsoncms\api\generated\User $admin Try to find generic user */
        $admin = $this->query
            ->entity($this->social->dbTable)
            ->where($this->social->dbEmailField, $adminUser)
            ->first();

        // Create user record if missing
        if (!isset($admin)) {
            $admin = new $this->social->dbTable();
        }

        // Fill in user credentials according to config
        $admin[$this->social->dbEmailField] = $adminUser;
        $admin[$this->social->dbHashEmailField] = $hashedEmailValue;
        $admin[$this->social->dbHashPasswordField] = $hashedEmailValue;
        $admin->fName = 'admin';
        $admin->sName = '';
        $admin->tName = '';
        $admin->groupId = 1;
        $admin->system = 1;
        $admin->created = date('Y-m-d H:i:s');
        $admin->active = 1;
        $admin->save();
    }
    //[PHPCOMPRESSOR(remove,end)]

    /** Check the user's authorization */
    public function __HANDLER()
    {
        $this->authorize($this->social);
    }

    /** Main sign in template */
    public function __base()
    {
        // Change template
        $this->system->template('www/signin/signin_template.vphp');

        // Render template with sign in form
        $this->html($this->view('www/signin/signin_form')->output())
            ->title(t('Авторизация', true));
    }

    /** User asynchronous sign in */
    public function __async_login()
    {
        $user = null;
        $error = '';

        if (isset($_POST['email']) && isset($_POST['password'])) {
            $email = $this->social->hash($_POST['email']);
            $password = $this->social->hash($_POST['password']);
            $remember = isset($_POST['remember']) ? true : false;

            /** @var EmailStatus Perform email authorization */
            $auth = $this->social->authorizeWithEmail($email, $password, $remember, $user);

            if ($auth->code === EmailStatus::SUCCESS_EMAIL_AUTHORIZE) {
                // Fire login success event
                Event::fire('samson.cms.signin.login', array(&$user));

                return array('status' => '1');
            } else {
                $error .= $this->view('www/signin/signin_form.vphp')
                    ->errorClass('errorAuth')
                    ->userEmail("{$_POST['email']}")
                    ->focus('autofocus')
                    ->output();

                return array('status' => '0', 'html' => $error);
            }
        } else {
            $error .= $this->view('www/signin/signin_form')->errorClass('errorAuth')->output();

            return array('status' => '0', 'html' => $error);
        }
    }

    /** User logout */
    public function __logout()
    {
        $this->social->deauthorize();

        // Fire logout event
        Event::fire('samson.cms.signin.logout');

        $this->request->redirect('cms/signin');
    }

    /** Sending email with the correct address */
    public function __mail()
    {
        if (isset($_POST['email'])) {
            /** @var \samson\activerecord\user $user */
            $user = null;
            $result = '';

            if (!empty($user = (new UserQuery())->email($_POST['email'])->first())) {
                $user->confirmed = $this->social->hash(generate_password(20) . time());
                $user->save();

                $message = $this->view('www/signin/email/pass_recovery')->code($user->confirmed)->output();
                mail_send($user->email, 'info@samsonos.com', $message, t('Восстановление пароля!', true), 'SamsonCMS');

                $result .= $this->view('www/signin/pass_recovery_mailsend')->output();
                $this->system->template('www/signin/signin_template.vphp');
                $this->html($result)->title(t('Восстановление пароля', true));
            } else {
                $this->request->redirect();
            }
        } else {
            $this->request->redirect();
        }
    }

    /**
     * New password form.
     *
     * @param string $code Code password recovery
     *
     * @return bool
     */
    public function __confirm($code)
    {
        $code = substr($code, 0, 32);
        $rights = (new UserQuery())->confirmed($code)->first();

        if (!empty($rights)) {
            $this->system->template('www/signin/signin_template.vphp');
            $this->html($this->view('www/signin/new_pass_form')->code($code)->output())
                ->title(t('Восстановление пароля', true));
        } else {
            return A_FAILED;
        }
    }

    /**
     * Setting new password and sign in
     *
     * @param string $code Code password recovery
     */
    public function __recovery($code)
    {
        if (isset($_POST['password']) && isset($_POST['confirm_password'])
            && $_POST['password'] == $_POST['confirm_password']
        ) {
            /** @var \samson\activerecord\user $user */
            $user = null;
            if (!empty($user = (new UserQuery())->confirmed($code)->first())) {
                $user->confirmed = 1;
                $user->md5_password = md5($_POST['password']);
                $user->hash_password = md5($_POST['password']);
                $user->save();

                $auth = $this->social->authorizeWithEmail($user->md5_email, $user->md5_password, $user);
                if ($auth->code === EmailStatus::SUCCESS_EMAIL_AUTHORIZE) {
                    $this->request->redirect();
                }
            }
        } else {
            $result = '';
            $result .= m()->view('www/signin/pass_error')
                ->message(t('Вы ввели некорректный пароль либо пароли не совпадают', true))
                ->output();
            $this->system->template('www/signin/signin_template.vphp');
            $this->html($result)->title(t('Ошибка восстановление пароля', true));
        }
    }
}
