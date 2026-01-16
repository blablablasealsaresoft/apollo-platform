import Joi from 'joi';

export const mfaTokenSchema = Joi.object({
  userId: Joi.string().uuid().optional(),
  token: Joi.string().length(6).pattern(/^[0-9]+$/).required(),
});

export const disableMfaSchema = Joi.object({
  password: Joi.string().required(),
});
