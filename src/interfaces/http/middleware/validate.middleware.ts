import { z } from 'zod';
import { NextFunction, Request, Response } from 'express';

/**
 * Middleware factory de validación con Zod.
 *
 * Valida req.body contra el schema dado. Si la validación falla, retorna 400
 * con los issues detallados de Zod. Si tiene éxito, reemplaza req.body con el
 * valor parseado (con defaults y coerciones de Zod aplicados).
 *
 * @example
 * router.post('/keys/managed/create', validate(CreateKeySchema), controller.createManagedKey);
 */
export function validate(schema: z.ZodSchema) {
    return (req: Request, res: Response, next: NextFunction): void => {
        const result = schema.safeParse(req.body);
        if (!result.success) {
            res.status(400).json({
                ok: false,
                error: 'Validation error',
                issues: result.error.issues.map((i) => ({
                    path: i.path.join('.'),
                    message: i.message,
                })),
            });
            return;
        }
        req.body = result.data;
        next();
    };
}
