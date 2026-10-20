<?php
$api = getenv('NATIVE_MACHINE_API');
if (!is_string($api) || !str_starts_with($api, '/')) throw new RuntimeException('NATIVE_MACHINE_API_REQUIRED');
require $api.'/vendor/autoload.php';
$app = require $api.'/bootstrap/app.php';
$app->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use App\Models\Plan;
use App\Models\Server;
use App\Models\ServerGroup;
use App\Models\ServerMachine;
use App\Models\User;
use App\Services\NodeSyncService;
use App\Services\DeviceStateService;
if (!app()->environment('testing') || config('database.default') !== 'mysql'
 || DB::connection()->getDatabaseName() !== 'txboard_native_machine_test'
 || config('database.connections.mysql.host') !== '127.0.0.1'
 || config('database.connections.mysql.username') !== 'txboard_native_machine'
 || config('core_installation.mode') !== 'legacy' || config('node_ws.native_enabled') !== true
 || config('cache.default') !== 'redis' || config('cache.setting_store') !== 'redis') {
 fwrite(STDERR,"NATIVE_MACHINE_EXCLUSIVE_FIXTURE_REQUIRED\n"); exit(2);
}
$mode = $argv[1] ?? '';
$directory = getenv('NATIVE_MACHINE_DIR');
if ($mode === 'seed') {
 foreach (['tx_user','tx_plan','tx_server','tx_server_group','tx_server_machine','tx_traffic_batch'] as $table) {
  if (DB::table($table)->exists()) throw new RuntimeException('NATIVE_MACHINE_NONEMPTY_FIXTURE_REFUSED');
 }
 $machine = ServerMachine::create(['name'=>'isolated-native-machine','token'=>'native-machine-local-test-only','is_active'=>true,'image_channel'=>'stable']);
 $nodes = [];
 foreach (['vless','vmess'] as $index=>$protocol) {
  $group = ServerGroup::unguarded(fn()=>ServerGroup::create(['name'=>'isolated-machine-group-'.$protocol]));
  $plan = Plan::create(['name'=>'isolated-machine-plan-'.$protocol,'group_id'=>$group->id,'transfer_enable'=>1,'prices'=>[Plan::PERIOD_MONTHLY=>1],'show'=>true,'sell'=>true,'renew'=>true,'reset_traffic_method'=>Plan::RESET_TRAFFIC_NEVER]);
  $port = (int)getenv('NATIVE_MACHINE_NODE_PORT_'.$index);
  $origin = (int)getenv('NATIVE_MACHINE_ORIGIN_PORT');
  if ($port<1024 || $port>65535 || $origin<1024 || $origin>65535 || $port===$origin) throw new RuntimeException('NATIVE_MACHINE_PORT_REFUSED');
  $node = Server::withoutEvents(fn()=>Server::create(['name'=>'isolated-machine-node-'.$protocol,'machine_id'=>$machine->id,'type'=>$protocol,'host'=>'127.0.0.1','port'=>$port,'server_port'=>$port,'rate'=>1,'group_ids'=>[(string)$group->id],'enabled'=>true,'show'=>true,'protocol_settings'=>['tls'=>0],
    'custom_routes'=>[['network'=>'tcp','ip_cidr'=>['127.0.0.1/32'],'port'=>[$origin],'outbound'=>'direct']]]));
  $uuid = $index===0 ? '00112233-4455-4677-8899-aabbccddeeff' : 'ffeeddcc-bbaa-4998-8776-554433221100';
  $user = User::withoutEvents(fn()=>User::create(['email'=>'isolated-machine-'.$protocol.'@example.test','password'=>Hash::make('SyntheticMachineUser2026'),'uuid'=>$uuid,'token'=>'isolated-machine-user-'.$protocol,'plan_id'=>$plan->id,'group_id'=>$group->id,'transfer_enable'=>1073741824,'u'=>0,'d'=>0,'expired_at'=>time()+3600,'banned'=>false]));
  $nodes[]=['id'=>(int)$node->id,'user_id'=>(int)$user->id,'protocol'=>$protocol,'port'=>$port,'uuid'=>$uuid];
 }
 $foreignMachine = ServerMachine::create(['name'=>'isolated-foreign-machine','token'=>'foreign-machine-local-test-only','is_active'=>true,'image_channel'=>'stable']);
 $foreignNode = Server::withoutEvents(fn()=>Server::create(['name'=>'isolated-foreign-node','machine_id'=>$foreignMachine->id,'type'=>'vless','host'=>'127.0.0.1','port'=>(int)getenv('NATIVE_MACHINE_FOREIGN_PORT'),'server_port'=>(int)getenv('NATIVE_MACHINE_FOREIGN_PORT'),'rate'=>1,'group_ids'=>[],'enabled'=>true,'show'=>true,'protocol_settings'=>['tls'=>0]]));
 User::withoutEvents(fn()=>User::create(['email'=>'native-machine-admin@example.test','password'=>Hash::make('SyntheticMachineAdmin2026'),'uuid'=>'00112233-4455-4677-8899-aabbccddee00','token'=>'private-machine-admin','is_admin'=>true,'banned'=>false,'u'=>0,'d'=>0]));
 admin_setting(['server_token'=>'native-machine-unused-standalone','secure_path'=>'native_machine_admin','captcha_enable'=>0,'password_limit_enable'=>0,'server_pull_interval'=>1,'server_push_interval'=>60]);
 echo json_encode(['machine_id'=>(int)$machine->id,'token'=>$machine->token,'nodes'=>$nodes,'foreign_machine_id'=>(int)$foreignMachine->id,'foreign_node_id'=>(int)$foreignNode->id,'foreign_token'=>$foreignMachine->token,'origin_port'=>(int)getenv('NATIVE_MACHINE_ORIGIN_PORT'),'new_port'=>(int)getenv('NATIVE_MACHINE_NEW_PORT')],JSON_THROW_ON_ERROR)."\n";
 exit(0);
}
$fixture = json_decode(file_get_contents($directory.'/fixture.json'),true,32,JSON_THROW_ON_ERROR);
if ($mode === 'state') {
 $machine = ServerMachine::findOrFail($fixture['machine_id']);
 $result = ['machine_id'=>(int)$machine->id,'machine_online'=>NodeSyncService::isMachineOnline((int)$machine->id),'nodes'=>[],'batches'=>DB::table('tx_traffic_batch')->orderBy('server_id')->orderBy('batch_id')->get(['server_id','batch_id','payload_hash'])->toArray()];
 foreach ($fixture['nodes'] as $row) {
  $node = Server::findOrFail($row['id']); $user = User::findOrFail($row['user_id']);
  $result['nodes'][]=['id'=>(int)$node->id,'enabled'=>(bool)$node->enabled,'port'=>(int)$node->server_port,'ws_online'=>NodeSyncService::isNodeOnline((int)$node->id),'devices'=>app(DeviceStateService::class)->getNodeDevices((int)$node->id),'u'=>(string)$user->u,'d'=>(string)$user->d];
 }
 echo json_encode($result,JSON_THROW_ON_ERROR)."\n"; exit(0);
}
throw new RuntimeException('NATIVE_MACHINE_MODE_REQUIRED');
