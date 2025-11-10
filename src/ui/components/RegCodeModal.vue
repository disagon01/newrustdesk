<template>
  <el-dialog 
    title="远程连接授权" 
    v-model="visible" 
    width="420px" 
    :close-on-click-modal="false"
    :close-on-press-escape="false"
  >
    <el-form :model="form" :rules="rules" ref="formRef" label-width="80px">
      <el-form-item label="机器码" prop="machineCode">
        <el-input 
          v-model="form.machineCode" 
          readonly 
          placeholder="14位设备唯一标识"
          class="machine-code-input"
        />
        <el-button 
          type="text" 
          size="small" 
          @click="copyMachineCode"
          class="copy-btn"
        >
          复制
        </el-button>
      </el-form-item>
      <el-form-item label="注册码" prop="regCode">
        <el-input 
          v-model="form.regCode" 
          placeholder="请输入注册码"
          clearable
        />
      </el-form-item>
      <el-form-item>
        <el-alert 
          title="重要提示" 
          type="warning" 
          :closable="false"
          size="small"
        >
          1. 注册码与设备绑定，请勿泄露给他人<br>
          2. 系统将自动检测时间篡改，篡改时间将强制重新验证<br>
          3. 注册码过期后需联系管理员重新获取
        </el-alert>
      </el-form-item>
    </el-form>
    <template #footer>
      <el-button @click="handleCancel">取消</el-button>
      <el-button type="primary" @click="handleVerify" :loading="isVerifying">
        {{ isVerifying ? '验证中...' : '验证并连接' }}
      </el-button>
    </template>
  </el-dialog>
</template>

<script setup>
import { ref, onMounted } from 'vue';
import { ElDialog, ElForm, ElFormItem, ElInput, ElButton, ElMessage, ElAlert } from 'element-plus';
import { getMachineCode, verifyRegCode } from '@/utils/auth';
import { useClipboard } from '@vueuse/core';

const { copy, isSupported } = useClipboard();

// 弹窗状态
const visible = ref(false);
const isVerifying = ref(false); // 验证中加载状态
// 表单数据
const form = ref({
  machineCode: '',
  regCode: ''
});
// 表单校验
const rules = ref({
  regCode: [{ required: true, message: '请输入注册码', trigger: 'blur' }]
});
const formRef = ref(null);
// 验证成功回调
const onVerifySuccess = ref(null);

// 打开弹窗
const openModal = (successCallback) => {
  onVerifySuccess.value = successCallback;
  visible.value = true;
};

// 页面挂载时生成机器码
onMounted(() => {
  form.value.machineCode = getMachineCode();
});

// 关闭弹窗
const handleCancel = () => {
  visible.value = false;
  formRef.value?.resetFields();
};

// 复制机器码
const copyMachineCode = async () => {
  if (isSupported) {
    await copy(form.value.machineCode);
    ElMessage.success('机器码已复制到剪贴板');
  } else {
    ElMessage.warning('无法复制，请手动选中复制');
  }
};

// 校验注册码（新增时间篡改检测逻辑）
const handleVerify = async () => {
  try {
    await formRef.value?.validate();
    isVerifying.value = true; // 开始验证，显示加载

    // 调用带时间篡改检测的验证函数
    const verifyRes = verifyRegCode(form.value.machineCode, form.value.regCode);
    if (verifyRes.success) {
      ElMessage.success('验证通过，正在连接...');
      onVerifySuccess.value(); // 执行原连接逻辑
      visible.value = false;
    } else {
      ElMessage.error(verifyRes.message);
    }
  } catch (error) {
    ElMessage.error('请检查注册码格式');
  } finally {
    isVerifying.value = false; // 验证结束，关闭加载
  }
};

// 暴露方法给父组件
defineExpose({ openModal });
</script>

<style scoped>
.machine-code-input {
  width: 85%;
  display: inline-block;
}
.copy-btn {
  vertical-align: middle;
}
</style>
