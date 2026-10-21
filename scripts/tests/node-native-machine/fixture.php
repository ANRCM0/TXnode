<?php
$api = getenv('NATIVE_MACHINE_API');
if (!is_string($api) || !str_starts_with($api, '/')) throw new RuntimeException('NATIVE_MACHINE_API_REQUIRED');
require $api.'/vendor/autoload.php';
$app = require $api.'/bootstrap/app.php';
$app->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Artisan;
use App\Models\Plan;
use App\Models\Order;
use App\Models\Server;
use App\Models\ServerGroup;
use App\Models\ServerMachine;
use App\Models\User;
use App\Services\NodeSyncService;
use App\Services\DeviceStateService;
use App\Domains\Installation\InstallationAuthority;
use App\Domains\Network\NativeNodeAuthorization;
use App\Domains\Subscription\Services\NativeCredentialProviderService;
use App\Domains\Subscription\Services\PlanPublicationService;
if (!app()->environment('testing') || config('database.default') !== 'mysql'
 || DB::connection()->getDatabaseName() !== 'txboard_native_machine_test'
 || config('database.connections.mysql.host') !== '127.0.0.1'
 || config('database.connections.mysql.username') !== 'txboard_native_machine'
 || config('node_ws.native_enabled') !== true
 || config('cache.default') !== 'redis' || config('cache.setting_store') !== 'redis') {
 fwrite(STDERR,"NATIVE_MACHINE_EXCLUSIVE_FIXTURE_REQUIRED\n"); exit(2);
}
$mode = $argv[1] ?? '';
$directory = getenv('NATIVE_MACHINE_DIR');
function machinePrivate(string $path, mixed $value): void {
 $file = fopen($path, 'x');
 if ($file === false || !chmod($path, 0600)) throw new RuntimeException('NATIVE_MACHINE_PRIVATE_FILE_REQUIRED');
 try { if (fwrite($file, is_string($value) ? $value : json_encode($value, JSON_THROW_ON_ERROR)) === false || !fflush($file) || !fsync($file)) throw new RuntimeException('NATIVE_MACHINE_PRIVATE_WRITE_FAILED'); }
 finally { fclose($file); }
}
// Same public HTTP -> native free checkout -> durable worker owners as Core C2.
function machineRequest(string $path, array $payload, ?string $bearer = null, ?string $key = null, array $statuses = [200]): array {
 $handle = curl_init(getenv('TXBOARD_NATIVE_MACHINE_URL').'/txapi/'.$path);
 $headers = ['Content-Type: application/json','Accept: application/json'];
 if ($bearer !== null) $headers[] = 'Authorization: '.$bearer;
 if ($key !== null) $headers[] = 'Idempotency-Key: '.$key;
 curl_setopt_array($handle, [CURLOPT_POST=>true,CURLOPT_POSTFIELDS=>json_encode($payload,JSON_THROW_ON_ERROR),CURLOPT_RETURNTRANSFER=>true,CURLOPT_HTTPHEADER=>$headers,CURLOPT_CAINFO=>getenv('NATIVE_MACHINE_DIR').'/ca.pem',CURLOPT_SSL_VERIFYPEER=>true,CURLOPT_SSL_VERIFYHOST=>2,CURLOPT_PROTOCOLS=>CURLPROTO_HTTPS,CURLOPT_FOLLOWLOCATION=>false,CURLOPT_PROXY=>'',CURLOPT_TIMEOUT=>20]);
 $raw = curl_exec($handle); $status = curl_getinfo($handle,CURLINFO_RESPONSE_CODE); curl_close($handle);
 if (!is_string($raw) || strlen($raw)>1048576 || !in_array($status,$statuses,true)) throw new RuntimeException('NATIVE_MACHINE_OWNER_HTTP_'.$status);
 return json_decode($raw,true,64,JSON_THROW_ON_ERROR);
}
function machineWork(): void {
 if (Artisan::call('core:native-work',['--limit'=>100]) !== 0) throw new RuntimeException('NATIVE_MACHINE_OWNER_WORK_FAILED');
}
if ($mode === 'trust') {
 $trust = app(NativeNodeAuthorization::class)->publicTrust();
 machinePrivate($directory.'/trust.json', ['protocol_version'=>1,'core_instance_id'=>$trust['core_instance_id'],'key_id'=>$trust['key_id'],'key_epoch'=>$trust['key_epoch'],'algorithm'=>'Ed25519','public_key'=>$trust['public_key']]);
 echo json_encode($trust,JSON_THROW_ON_ERROR)."\n"; exit(0);
}
if ($mode === 'seed') {
 foreach (['tx_user','tx_plan','tx_server','tx_server_group','tx_server_machine','tx_usage_batch'] as $table) {
  if (DB::table($table)->exists()) throw new RuntimeException('NATIVE_MACHINE_NONEMPTY_FIXTURE_REFUSED');
 }
 if (config('core_installation.mode') !== 'native' || config('native_node_authorization.policy_version') !== 'native-provider-authorization/v2') throw new RuntimeException('NATIVE_MACHINE_NATIVE_CONFIGURATION_REQUIRED');
 app(InstallationAuthority::class)->initialize('11111111-1111-4111-8111-111111111111','native','machine-native-bootstrap');
 $machine = ServerMachine::create(['name'=>'isolated-native-machine','token'=>bin2hex(random_bytes(24)),'is_active'=>true,'image_channel'=>'stable']);
 $nodes = []; $recipients = [];
 foreach (['vless','vmess'] as $index=>$protocol) {
  $group = ServerGroup::unguarded(fn()=>ServerGroup::create(['name'=>'isolated-machine-group-'.$protocol]));
  $plan = Plan::withoutEvents(fn()=>Plan::create(['name'=>'isolated-machine-plan-'.$protocol,'group_id'=>$group->id,'transfer_enable'=>1,'prices'=>['monthly'=>'0.00','reset_traffic'=>'0.00'],'show'=>true,'sell'=>true,'renew'=>true,'reset_traffic_method'=>2]));
  $published = app(PlanPublicationService::class)->publish($plan->id,'machine-publish-'.$protocol,'USD','UTC');
  $offer = collect($published['offers'])->firstWhere('offer_code','monthly');
  $port = (int)getenv('NATIVE_MACHINE_NODE_PORT_'.$index); $origin = (int)getenv('NATIVE_MACHINE_ORIGIN_PORT');
  if ($port<1024 || $port>65535 || $origin<1024 || $origin>65535 || $port===$origin) throw new RuntimeException('NATIVE_MACHINE_PORT_REFUSED');
  $node = Server::withoutEvents(fn()=>Server::create(['name'=>'isolated-machine-node-'.$protocol,'machine_id'=>$machine->id,'type'=>$protocol,'host'=>'127.0.0.1','port'=>$port,'server_port'=>$port,'rate'=>1,'group_ids'=>[(string)$group->id],'enabled'=>true,'show'=>true,'protocol_settings'=>['tls'=>0,'network'=>'tcp'],
    'custom_routes'=>[['network'=>'tcp','ip_cidr'=>['127.0.0.1/32'],'port'=>[$origin],'outbound'=>'direct']]]));
  $recipients[$node->id] = ['machine_id'=>(int)$machine->id,'recipient_sha256'=>getenv('NATIVE_MACHINE_RECIPIENT_SHA256')];
  $nodes[] = ['id'=>(int)$node->id,'protocol'=>$protocol,'port'=>$port,'offer_id'=>(int)$offer['offer_id']];
 }
 $foreignMachine = ServerMachine::create(['name'=>'isolated-foreign-machine','token'=>bin2hex(random_bytes(24)),'is_active'=>true,'image_channel'=>'stable']);
 $foreignGroup = ServerGroup::unguarded(fn()=>ServerGroup::create(['name'=>'isolated-foreign-group']));
 $foreignNode = Server::withoutEvents(fn()=>Server::create(['name'=>'isolated-foreign-node','machine_id'=>$foreignMachine->id,'type'=>'vless','host'=>'127.0.0.1','port'=>(int)getenv('NATIVE_MACHINE_FOREIGN_PORT'),'server_port'=>(int)getenv('NATIVE_MACHINE_FOREIGN_PORT'),'rate'=>1,'group_ids'=>[(string)$foreignGroup->id],'enabled'=>true,'show'=>true,'protocol_settings'=>['tls'=>0,'network'=>'tcp']]));
 $recipients[$foreignNode->id] = ['machine_id'=>(int)$foreignMachine->id,'recipient_sha256'=>getenv('NATIVE_MACHINE_RECIPIENT_SHA256')];
 file_put_contents($directory.'/recipients.json',json_encode((object)$recipients,JSON_THROW_ON_ERROR)); chmod($directory.'/recipients.json',0600);
 config(['native_provider_node.recipients'=>$recipients]);
 User::withoutEvents(fn()=>User::create(['email'=>'native-machine-admin@example.test','password'=>Hash::make('SyntheticMachineAdmin2026'),'uuid'=>'','token'=>'','is_admin'=>true,'banned'=>false,'u'=>0,'d'=>0,'transfer_enable'=>0,'balance'=>0,'commission_balance'=>0]));
 admin_setting(['server_token'=>'native-machine-unused-standalone','secure_path'=>'native_machine_admin','captcha_enable'=>0,'password_limit_enable'=>0,'stop_register'=>0,'email_verify'=>0,'server_pull_interval'=>1,'server_push_interval'=>60]);
 app(NativeCredentialProviderService::class)->register('primary-provider','machine-native-provider');
 $authority = app(InstallationAuthority::class); $ready = $authority->readiness();
 $activation = $authority->activate('machine-native-activate','1',$ready['configuration_digest']);
 if ($activation['phase'] !== 'open' || $activation['authority_epoch'] !== '2') throw new RuntimeException('NATIVE_MACHINE_REAL_ACTIVATION_REQUIRED');
 echo json_encode(['machine_id'=>(int)$machine->id,'token'=>$machine->token,'nodes'=>$nodes,'foreign_machine_id'=>(int)$foreignMachine->id,'foreign_node_id'=>(int)$foreignNode->id,'foreign_token'=>$foreignMachine->token,'origin_port'=>(int)getenv('NATIVE_MACHINE_ORIGIN_PORT'),'new_port'=>(int)getenv('NATIVE_MACHINE_NEW_PORT'),'activation'=>['phase'=>'open','authority_epoch'=>'2']],JSON_THROW_ON_ERROR)."\n"; exit(0);
}
$fixture = json_decode(file_get_contents($directory.'/fixture.json'),true,32,JSON_THROW_ON_ERROR);
if ($mode === 'account') {
 foreach ($fixture['nodes'] as $index=>&$row) {
  $email = 'machine-'.$row['protocol'].'@example.test';
  $registered = machineRequest('auth/register',['email'=>$email,'password'=>'SyntheticMachineUser2026'],statuses:[201]);
  $bearer = $registered['data']['auth_data']; machinePrivate($directory.'/user-bearer-'.$index,$bearer);
  $key = 'machine-purchase-'.$row['protocol'];
  $order = machineRequest('orders',['offer_id'=>$row['offer_id']],$bearer,$key,[201]); $trade = $order['data']['trade_no'];
  machineRequest('orders/'.$trade.'/checkout',[],$bearer,$key.'-checkout');
  machineRequest('orders/'.$trade.'/checkout',[],$bearer,$key.'-checkout');
  for ($attempt=0;$attempt<4;$attempt++) { machineWork(); if ((int)Order::where('trade_no',$trade)->value('status')===Order::STATUS_COMPLETED) break; }
  machineWork();
  $replay = machineRequest('orders',['offer_id'=>$row['offer_id']],$bearer,$key,[201]);
  if (($replay['data']['trade_no']??null)!==$trade || (int)Order::where('trade_no',$trade)->value('status')!==Order::STATUS_COMPLETED) throw new RuntimeException('NATIVE_MACHINE_REAL_FULFILLMENT_REQUIRED');
  $user = User::where('email',$email)->firstOrFail();
  $subscription = DB::table('tx_subscription_slot')->where('user_id',$user->id)->value('subscription_id');
  $subject = DB::table('tx_access_subject')->where('subscription_id',$subscription)->where('credential_profile_id',$row['protocol'].'-uuid/v1')->where('status','active')->first();
  if (!$subject || $user->uuid!=='' || $user->token!=='') throw new RuntimeException('NATIVE_MACHINE_PROVIDER_ISSUANCE_REQUIRED');
  $row += ['user_id'=>(int)$user->id,'subject_id'=>(string)$subject->id,'subscription_id'=>(string)$subscription,'initial_period_id'=>(string)DB::table('tx_usage_period')->where('subscription_id',$subscription)->value('id')];
 }
 unset($row);
 if (DB::table('tx_payment_receipt')->exists() || DB::table('tx_money_journal')->exists()) throw new RuntimeException('NATIVE_MACHINE_FREE_CHECKOUT_REQUIRED');
 echo json_encode($fixture,JSON_THROW_ON_ERROR)."\n"; exit(0);
}
if ($mode === 'work') { machineWork(); echo "native worker scanned\n"; exit(0); }
if ($mode === 'state') {
 machineWork();
 $machine = ServerMachine::findOrFail($fixture['machine_id']);
 $result = ['machine_id'=>(int)$machine->id,'machine_online'=>NodeSyncService::isMachineOnline((int)$machine->id),'nodes'=>[],
  'batches'=>DB::table('tx_usage_batch')->orderBy('node_id')->orderBy('source_epoch')->orderBy('batch_id')->get(['node_id','source_epoch','batch_id','payload_digest','canonical_payload','frozen_entries','status'])->toArray()];
 foreach ($fixture['nodes'] as $row) {
  $node = Server::findOrFail($row['id']); $user = User::findOrFail($row['user_id']);
  $result['nodes'][]=['id'=>(int)$node->id,'enabled'=>(bool)$node->enabled,'port'=>(int)$node->server_port,'ws_online'=>NodeSyncService::isNodeOnline((int)$node->id),'devices'=>app(DeviceStateService::class)->getNodeDevices((int)$node->id),'u'=>(string)$user->u,'d'=>(string)$user->d];
 }
 echo json_encode($result,JSON_THROW_ON_ERROR)."\n"; exit(0);
}
throw new RuntimeException('NATIVE_MACHINE_MODE_REQUIRED');
