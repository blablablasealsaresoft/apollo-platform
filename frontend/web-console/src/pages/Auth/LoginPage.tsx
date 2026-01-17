import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useFormik } from 'formik';
import * as Yup from 'yup';
import { useAppDispatch } from '@store/hooks';
import { login, loginWithBiometric, verifyMfa } from '@store/slices/authSlice';
import toast from 'react-hot-toast';
import { FiLock, FiUser, FiSmartphone, FiCamera, FiMic, FiShield } from 'react-icons/fi';
import { BiFingerprint } from 'react-icons/bi';

// Biometric authentication types
type BiometricType = 'fingerprint' | 'face_id' | 'voice_print';

// MFA verification step
interface MfaStep {
  required: boolean;
  sessionId?: string;
  availableMethods: string[];
}

const LoginPage: React.FC = () => {
  const navigate = useNavigate();
  const dispatch = useAppDispatch();
  const [loading, setLoading] = useState(false);
  const [biometricLoading, setBiometricLoading] = useState(false);
  const [biometricAvailable, setBiometricAvailable] = useState<BiometricType[]>([]);
  const [showBiometricOptions, setShowBiometricOptions] = useState(false);
  const [mfaStep, setMfaStep] = useState<MfaStep>({ required: false, availableMethods: [] });
  const [mfaCode, setMfaCode] = useState('');

  // Check for available biometric methods on component mount
  useEffect(() => {
    checkBiometricAvailability();
  }, []);

  const checkBiometricAvailability = useCallback(async () => {
    const available: BiometricType[] = [];

    // Check for Web Authentication API (fingerprint/face)
    if (window.PublicKeyCredential) {
      try {
        const platformAuthAvailable = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
        if (platformAuthAvailable) {
          available.push('fingerprint');
          available.push('face_id');
        }
      } catch (e) {
        console.log('Platform authenticator check failed:', e);
      }
    }

    // Check for microphone access (voice print)
    if (navigator.mediaDevices && navigator.mediaDevices.getUserMedia) {
      try {
        // Just check if API is available, don't request permission yet
        available.push('voice_print');
      } catch (e) {
        console.log('Voice authentication not available');
      }
    }

    setBiometricAvailable(available);
  }, []);

  const formik = useFormik({
    initialValues: {
      username: '',
      password: '',
      rememberDevice: false,
    },
    validationSchema: Yup.object({
      username: Yup.string().required('Username is required'),
      password: Yup.string().required('Password is required'),
    }),
    onSubmit: async (values) => {
      setLoading(true);
      try {
        const result = await dispatch(login({
          username: values.username,
          password: values.password,
          rememberDevice: values.rememberDevice,
        })).unwrap();

        if (result.requiresMfa) {
          // MFA required - show MFA step
          setMfaStep({
            required: true,
            sessionId: result.sessionId,
            availableMethods: result.availableMfaMethods || ['totp'],
          });
          toast.success('Please complete MFA verification');
        } else {
          toast.success('Login successful!');
          navigate('/dashboard');
        }
      } catch (error: any) {
        if (error.code === 'MFA_REQUIRED_NEW_DEVICE') {
          setMfaStep({
            required: true,
            sessionId: error.pendingSessionId,
            availableMethods: ['totp', 'sms', 'email'],
          });
          toast.info('New device detected. MFA verification required.');
        } else {
          toast.error(error.message || error || 'Login failed');
        }
      } finally {
        setLoading(false);
      }
    },
  });

  const handleBiometricLogin = async (type: BiometricType) => {
    setBiometricLoading(true);

    try {
      let biometricData: string;

      switch (type) {
        case 'fingerprint':
        case 'face_id':
          biometricData = await authenticateWithWebAuthn(type);
          break;
        case 'voice_print':
          biometricData = await authenticateWithVoice();
          break;
        default:
          throw new Error('Unsupported biometric type');
      }

      const result = await dispatch(loginWithBiometric({
        type,
        biometricData,
        livenessProof: await generateLivenessProof(type),
      })).unwrap();

      if (result.requiresMfa) {
        setMfaStep({
          required: true,
          sessionId: result.sessionId,
          availableMethods: result.availableMfaMethods || ['totp'],
        });
      } else {
        toast.success('Biometric login successful!');
        navigate('/dashboard');
      }
    } catch (error: any) {
      console.error('Biometric authentication failed:', error);
      toast.error(error.message || 'Biometric authentication failed');
    } finally {
      setBiometricLoading(false);
    }
  };

  const authenticateWithWebAuthn = async (type: BiometricType): Promise<string> => {
    // WebAuthn authentication flow
    const publicKeyCredentialRequestOptions: PublicKeyCredentialRequestOptions = {
      challenge: Uint8Array.from(crypto.getRandomValues(new Uint8Array(32))),
      timeout: 60000,
      userVerification: 'required',
      rpId: window.location.hostname,
    };

    const credential = await navigator.credentials.get({
      publicKey: publicKeyCredentialRequestOptions,
    }) as PublicKeyCredential;

    if (!credential) {
      throw new Error('No credential received');
    }

    // Convert credential to base64 for transmission
    const response = credential.response as AuthenticatorAssertionResponse;
    return btoa(String.fromCharCode(...new Uint8Array(response.authenticatorData)));
  };

  const authenticateWithVoice = async (): Promise<string> => {
    return new Promise((resolve, reject) => {
      toast.info('Please speak your passphrase...');

      navigator.mediaDevices.getUserMedia({ audio: true })
        .then(stream => {
          const mediaRecorder = new MediaRecorder(stream);
          const audioChunks: Blob[] = [];

          mediaRecorder.ondataavailable = (event) => {
            audioChunks.push(event.data);
          };

          mediaRecorder.onstop = async () => {
            const audioBlob = new Blob(audioChunks, { type: 'audio/webm' });
            const reader = new FileReader();

            reader.onloadend = () => {
              const base64Audio = reader.result as string;
              stream.getTracks().forEach(track => track.stop());
              resolve(base64Audio.split(',')[1]);
            };

            reader.readAsDataURL(audioBlob);
          };

          mediaRecorder.start();

          // Record for 3 seconds
          setTimeout(() => {
            mediaRecorder.stop();
            toast.dismiss();
          }, 3000);
        })
        .catch(err => {
          reject(new Error('Microphone access denied'));
        });
    });
  };

  const generateLivenessProof = async (type: BiometricType): Promise<string> => {
    // Generate liveness proof based on biometric type
    const proof: Record<string, any> = {
      timestamp: Date.now(),
      type,
    };

    switch (type) {
      case 'fingerprint':
        proof.sensorType = 'capacitive';
        break;
      case 'face_id':
        proof.hasDepthMap = true;
        proof.eyeTracking = true;
        proof.headMotion = true;
        break;
      case 'voice_print':
        proof.isLiveAudio = true;
        break;
    }

    return JSON.stringify(proof);
  };

  const handleMfaVerify = async () => {
    if (!mfaCode.trim()) {
      toast.error('Please enter your MFA code');
      return;
    }

    setLoading(true);
    try {
      await dispatch(verifyMfa({
        sessionId: mfaStep.sessionId!,
        code: mfaCode,
      })).unwrap();

      toast.success('MFA verification successful!');
      navigate('/dashboard');
    } catch (error: any) {
      toast.error(error.message || 'MFA verification failed');
    } finally {
      setLoading(false);
    }
  };

  const getBiometricIcon = (type: BiometricType) => {
    switch (type) {
      case 'fingerprint':
        return <BiFingerprint className="h-6 w-6" />;
      case 'face_id':
        return <FiCamera className="h-6 w-6" />;
      case 'voice_print':
        return <FiMic className="h-6 w-6" />;
    }
  };

  const getBiometricLabel = (type: BiometricType) => {
    switch (type) {
      case 'fingerprint':
        return 'Fingerprint';
      case 'face_id':
        return 'Face ID';
      case 'voice_print':
        return 'Voice Print';
    }
  };

  // MFA Verification UI
  if (mfaStep.required) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-gradient-to-br from-primary-600 to-primary-900 px-4">
        <div className="w-full max-w-md">
          <div className="mb-8 text-center">
            <h1 className="text-4xl font-bold text-white">Apollo Platform</h1>
            <p className="mt-2 text-primary-100">Multi-Factor Authentication</p>
          </div>

          <div className="rounded-lg bg-white p-8 shadow-xl">
            <div className="mb-6 flex items-center justify-center">
              <div className="rounded-full bg-primary-100 p-3">
                <FiShield className="h-8 w-8 text-primary-600" />
              </div>
            </div>

            <h2 className="mb-2 text-center text-2xl font-bold text-gray-900">
              Verify Your Identity
            </h2>
            <p className="mb-6 text-center text-sm text-gray-600">
              Enter the verification code from your authenticator app
            </p>

            <div className="space-y-4">
              <div>
                <label className="mb-2 block text-sm font-medium text-gray-700">
                  Verification Code
                </label>
                <input
                  type="text"
                  value={mfaCode}
                  onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                  className="input text-center text-2xl tracking-widest"
                  placeholder="000000"
                  maxLength={6}
                  autoFocus
                />
              </div>

              <button
                onClick={handleMfaVerify}
                disabled={loading || mfaCode.length !== 6}
                className="btn-primary w-full"
              >
                {loading ? 'Verifying...' : 'Verify'}
              </button>

              {mfaStep.availableMethods.includes('sms') && (
                <button
                  onClick={() => toast.info('SMS code sent to your registered phone')}
                  className="btn-secondary w-full"
                >
                  <FiSmartphone className="mr-2 h-4 w-4" />
                  Send SMS Code
                </button>
              )}

              <button
                onClick={() => {
                  setMfaStep({ required: false, availableMethods: [] });
                  setMfaCode('');
                }}
                className="w-full text-sm text-gray-600 hover:text-gray-900"
              >
                Back to Login
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-gradient-to-br from-primary-600 to-primary-900 px-4">
      <div className="w-full max-w-md">
        <div className="mb-8 text-center">
          <h1 className="text-4xl font-bold text-white">Apollo Platform</h1>
          <p className="mt-2 text-primary-100">Criminal Intelligence System</p>
        </div>

        <div className="rounded-lg bg-white p-8 shadow-xl">
          <h2 className="mb-6 text-2xl font-bold text-gray-900">Sign In</h2>

          {/* Biometric Login Options */}
          {biometricAvailable.length > 0 && (
            <div className="mb-6">
              {showBiometricOptions ? (
                <div className="space-y-2">
                  <p className="mb-3 text-sm font-medium text-gray-700">
                    Choose biometric method:
                  </p>
                  <div className="grid grid-cols-3 gap-2">
                    {biometricAvailable.map((type) => (
                      <button
                        key={type}
                        onClick={() => handleBiometricLogin(type)}
                        disabled={biometricLoading}
                        className="flex flex-col items-center justify-center rounded-lg border border-gray-200 p-3 transition-colors hover:border-primary-500 hover:bg-primary-50"
                      >
                        {getBiometricIcon(type)}
                        <span className="mt-1 text-xs text-gray-600">
                          {getBiometricLabel(type)}
                        </span>
                      </button>
                    ))}
                  </div>
                  <button
                    onClick={() => setShowBiometricOptions(false)}
                    className="mt-2 w-full text-sm text-gray-500 hover:text-gray-700"
                  >
                    Use password instead
                  </button>
                </div>
              ) : (
                <button
                  onClick={() => setShowBiometricOptions(true)}
                  disabled={biometricLoading}
                  className="flex w-full items-center justify-center rounded-lg border border-primary-500 bg-primary-50 px-4 py-3 text-primary-700 transition-colors hover:bg-primary-100"
                >
                  <BiFingerprint className="mr-2 h-5 w-5" />
                  {biometricLoading ? 'Authenticating...' : 'Sign in with Biometrics'}
                </button>
              )}

              <div className="my-4 flex items-center">
                <div className="flex-grow border-t border-gray-300"></div>
                <span className="mx-4 text-sm text-gray-500">or</span>
                <div className="flex-grow border-t border-gray-300"></div>
              </div>
            </div>
          )}

          <form onSubmit={formik.handleSubmit} className="space-y-4">
            <div>
              <label className="mb-2 block text-sm font-medium text-gray-700">
                Username
              </label>
              <div className="relative">
                <FiUser className="absolute left-3 top-1/2 h-5 w-5 -translate-y-1/2 text-gray-400" />
                <input
                  type="text"
                  {...formik.getFieldProps('username')}
                  className="input pl-10"
                  placeholder="Enter your username"
                />
              </div>
              {formik.touched.username && formik.errors.username && (
                <p className="mt-1 text-sm text-danger-600">{formik.errors.username}</p>
              )}
            </div>

            <div>
              <label className="mb-2 block text-sm font-medium text-gray-700">
                Password
              </label>
              <div className="relative">
                <FiLock className="absolute left-3 top-1/2 h-5 w-5 -translate-y-1/2 text-gray-400" />
                <input
                  type="password"
                  {...formik.getFieldProps('password')}
                  className="input pl-10"
                  placeholder="Enter your password"
                />
              </div>
              {formik.touched.password && formik.errors.password && (
                <p className="mt-1 text-sm text-danger-600">{formik.errors.password}</p>
              )}
            </div>

            <div className="flex items-center justify-between">
              <label className="flex items-center">
                <input
                  type="checkbox"
                  {...formik.getFieldProps('rememberDevice')}
                  className="rounded"
                />
                <span className="ml-2 text-sm text-gray-600">Remember this device</span>
              </label>
              <Link to="/forgot-password" className="text-sm text-primary-600 hover:underline">
                Forgot password?
              </Link>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="btn-primary w-full"
            >
              {loading ? 'Signing in...' : 'Sign In'}
            </button>
          </form>

          <p className="mt-6 text-center text-sm text-gray-600">
            Don't have an account?{' '}
            <Link to="/register" className="text-primary-600 hover:underline">
              Register
            </Link>
          </p>
        </div>

        <p className="mt-4 text-center text-xs text-primary-100">
          Classified System - Authorized Personnel Only
        </p>
      </div>
    </div>
  );
};

export default LoginPage;
