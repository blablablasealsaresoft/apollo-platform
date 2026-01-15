import React from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useFormik } from 'formik';
import * as Yup from 'yup';
import { useAppDispatch } from '@store/hooks';
import { register } from '@store/slices/authSlice';
import toast from 'react-hot-toast';

const RegisterPage: React.FC = () => {
  const navigate = useNavigate();
  const dispatch = useAppDispatch();

  const formik = useFormik({
    initialValues: {
      username: '',
      email: '',
      password: '',
      confirmPassword: '',
      firstName: '',
      lastName: '',
    },
    validationSchema: Yup.object({
      username: Yup.string().required('Required'),
      email: Yup.string().email('Invalid email').required('Required'),
      password: Yup.string().min(8, 'Minimum 8 characters').required('Required'),
      confirmPassword: Yup.string()
        .oneOf([Yup.ref('password')], 'Passwords must match')
        .required('Required'),
      firstName: Yup.string().required('Required'),
      lastName: Yup.string().required('Required'),
    }),
    onSubmit: async (values) => {
      try {
        await dispatch(register(values)).unwrap();
        toast.success('Registration successful!');
        navigate('/dashboard');
      } catch (error: any) {
        toast.error(error || 'Registration failed');
      }
    },
  });

  return (
    <div className="flex min-h-screen items-center justify-center bg-gradient-to-br from-primary-600 to-primary-900 px-4">
      <div className="w-full max-w-md">
        <div className="rounded-lg bg-white p-8 shadow-xl">
          <h2 className="mb-6 text-2xl font-bold">Register</h2>
          <form onSubmit={formik.handleSubmit} className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="mb-2 block text-sm font-medium">First Name</label>
                <input {...formik.getFieldProps('firstName')} className="input" />
              </div>
              <div>
                <label className="mb-2 block text-sm font-medium">Last Name</label>
                <input {...formik.getFieldProps('lastName')} className="input" />
              </div>
            </div>
            <div>
              <label className="mb-2 block text-sm font-medium">Username</label>
              <input {...formik.getFieldProps('username')} className="input" />
            </div>
            <div>
              <label className="mb-2 block text-sm font-medium">Email</label>
              <input type="email" {...formik.getFieldProps('email')} className="input" />
            </div>
            <div>
              <label className="mb-2 block text-sm font-medium">Password</label>
              <input type="password" {...formik.getFieldProps('password')} className="input" />
            </div>
            <div>
              <label className="mb-2 block text-sm font-medium">Confirm Password</label>
              <input
                type="password"
                {...formik.getFieldProps('confirmPassword')}
                className="input"
              />
            </div>
            <button type="submit" className="btn-primary w-full">
              Register
            </button>
          </form>
          <p className="mt-6 text-center text-sm">
            Already have an account?{' '}
            <Link to="/login" className="text-primary-600 hover:underline">
              Sign In
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
};

export default RegisterPage;
