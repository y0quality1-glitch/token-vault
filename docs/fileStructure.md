# Node.js + TypeScript Service Template — Reference Guide

This document describes the structure, conventions and base code of this template (`y0-utility-services` skeleton) so it can be reused as the starting point for another project. It also lists the bottlenecks and defects found in the current code, with recommended fixes.

---

## Table of Contents

1. [Tech Stack](#1-tech-stack)
2. [Folder Structure](#2-folder-structure)
3. [Architecture & Request Lifecycle](#3-architecture--request-lifecycle)
4. [Naming & Layering Conventions](#4-naming--layering-conventions)
5. [Base Code Files (copy-ready)](#5-base-code-files-copy-ready)
6. [Adding a New Module — Step by Step](#6-adding-a-new-module--step-by-step)
7. [Auto-generated CRUD Endpoints](#7-auto-generated-crud-endpoints)
8. [Response Contract & Error Codes](#8-response-contract--error-codes)
9. [Bottlenecks & Issues in the Current Code](#9-bottlenecks--issues-in-the-current-code)
10. [New-Project Bootstrap Checklist](#10-new-project-bootstrap-checklist)

---

## 1. Tech Stack

| Concern | Library | Notes |
|---|---|---|
| Runtime | Node.js 22 (alpine in Docker) | |
| Language | TypeScript 5.x → CommonJS, `build/` output | |
| HTTP | Express 5 | `express.json`, `urlencoded`, `multer`, `cors`, `helmet` |
| ORM | TypeORM 0.3 (Active Record via `BaseEntity`) | Postgres with read/write replication |
| Validation | `class-validator` + `class-transformer` | DTO classes |
| Auth | `jsonwebtoken` + DB session lookup (`user_logins`) | Bearer token |
| Payload encryption | `tweetnacl` secretbox (optional, `ENABLE_ENCRYPTION`) | |
| Hashing | `bcryptjs` | |
| Files | `multer` (memory) → AWS S3 (`aws-sdk` v2) | S3-compatible endpoint supported |
| Email | `nodemailer` | |
| API docs | `swagger-ui-express` (static spec object) | `/api-docs`, `/api-docs.json` |
| Tests | `vitest` + `supertest` | `__tests__` folders next to code |
| Dev | `ts-node`, `nodemon` | |
| Deploy | Multi-stage Dockerfile + `pm2-runtime` | |

---

## 2. Folder Structure

```
<project-root>/
├── .env.dev | .env.uat | .env.beta | .env.prod   # picked by NODE_ENV (git-ignored)
├── Dockerfile_<Service>                           # multi-stage build → pm2-runtime
├── nodemon.json                                   # dev watcher (ts-node src/index.ts)
├── package.json
├── tsconfig.json
├── send_notification.py                           # CI (GitHub Actions) email notifier
└── src/
    ├── index.ts                  # Entry: builds App with controller list, calls listen()
    ├── app.ts                    # Express app: middlewares, controllers, 404/405, DB bootstrap
    ├── config.ts                 # Loads .env.<env>, exports all constants & enums
    ├── swagger.ts                # Static OpenAPI spec + setupSwagger(app)
    │
    ├── controllers/
    │   ├── baseController.ts                 # ★ Abstract: registers CRUD routes, response/error helpers
    │   └── <module>Controller/
    │       ├── <module>Controller.controller.ts
    │       └── __tests__/*.test.ts
    │
    ├── services/
    │   ├── baseService.ts                    # ★ Abstract: generic CRUD + hooks (pre/post process), S3 files
    │   └── <module>Service/
    │       ├── <module>Service.service.ts
    │       └── __tests__/*.test.ts
    │
    ├── entities/                             # TypeORM entities (DB tables)
    │   └── y0Entity.ts                       # ★ Base entity: id, created_at, modified_at, is_delete
    │
    ├── databases/
    │   ├── dataSource.ts                     # TypeORM DataSource (master/slave, pool)
    │   ├── database.ts                       # Singleton: connectToDB, raw query, transactions
    │   └── repository/
    │       ├── y0Model/y0Model.model.ts      # ★ Base model (API shape) — { id }
    │       └── <module>/
    │           ├── <module>.model.ts         # Model: whitelist of accepted body fields
    │           └── <module>.dto.ts           # DTO: class-validator rules
    │
    ├── core/                                 # Framework-level building blocks
    │   ├── ApiError.ts                       # Typed errors + ApiError.handle(err, res)
    │   ├── ApiResponse.ts                    # Typed responses (+ optional encryption)
    │   ├── GenericResponse.ts                # Standard envelope used by BaseController
    │   ├── ErrorCodes.ts                     # E10xxx (generic) / E30xxx (domain) catalogue
    │   ├── AppRoutes.ts                      # APP_ROUTES enum (route prefixes) + SUCCESSMSG
    │   ├── MetaModel.ts                      # File-upload metadata per module
    │   ├── FileModel.ts                      # File interfaces
    │   ├── Y0Params.ts                       # Y0Params / Pagination / Filter param classes
    │   ├── AwsService.ts                     # S3 upload/delete/signed URL + Secrets Manager
    │   ├── Encryption&Decryption.ts          # NaCl encrypt/decrypt + bcrypt helpers
    │   ├── FileExistValidatorfn.ts           # class-validator constraint for files
    │   ├── EditValidatorfn.ts                # helper for ValidateIf on edit
    │   └── QueryLogger.ts                    # TypeORM logger implementation
    │
    ├── middlewares/
    │   ├── auth.middleware.ts                # JWT + session check
    │   ├── sanitizeBody.middleware.ts        # Strip body keys not on the Model
    │   ├── sanitizeFile.middleware.ts        # Keep only files declared in MetaModel
    │   └── validationFormData.middleware.ts  # DTO validation (body + files)
    │
    └── utils/
        ├── jwt/jwt.ts                        # create / verify / refresh token
        └── email/
            ├── EmailService.ts               # nodemailer wrapper
            └── emailTemplates.ts             # HTML templates (project-specific)
```

★ = base files every new module builds on.

---

## 3. Architecture & Request Lifecycle

```
           ┌──────────────────────────── app.ts (App) ─────────────────────────────┐
HTTP  ───► │ express.json / urlencoded → multer().any() → cors → helmet            │
request    │ → [optional] decrypt body (POST, ENABLE_ENCRYPTION)                    │
           │ → router mounted at PATH (e.g. /<service>/api/v1)                       │
           │      └─ <Module>Controller (extends BaseController)                     │
           │           route: authMiddleware → [validationFDMiddleware(DTO)] → handler│
           │           handler → <Module>Service (extends BaseServices)              │
           │                       └─ Entity (TypeORM BaseEntity) → Postgres         │
           │                       └─ AwsService → S3 (files)                        │
           │           sendResponse() → GenericResponse JSON                         │
           │ → 405 / 404 fallback (ApiError.handle)                                  │
           └─────────────────────────────────────────────────────────────────────────┘
```

**Pattern:** Template-Method. `BaseController` and `BaseServices` own the whole CRUD flow; a module only supplies
its Entity, Model, DTO, module name, optional `MetaModel`, and overrides hooks such as `createPreProcess`,
`postProcessAfterGetData`, `prepareQuery`, `getGolbalSearchColumns`.

**Service hooks (override as needed):**

| Flow | Hooks in order |
|---|---|
| `getAll` | `prepareFilter` → `applyGlobalSearch` → `getManyAndCount` → `postProcessAfterGetData` |
| `getById` | `findEntity` → `postProcessAfterGetById` |
| `createRecord` | `createPreProcess` (→ `transformModel`) → `findEntity` → `saveData` → `uploadFiles` → `updateFileData` → `createPostProcess` |
| `createMultiRecords` | `MultiPreProcess` → per item: same as create → `MultiPostProcess` |
| `deleteData` (hard) | `findEntity` → `deletePreProcess` → `getFilePathData` → `deleteFileData` → `deletePostProcess` |
| `updateDeleteFlagData` (soft) | `updateDeleteFlagPreProcess` → find → `UPDATE is_delete = 1` |
| `getData` (custom list) | `prepareQuery` (**must override**, return `{records,totalRecords}`) → `postProcessAfterGetAll` |
| `getDataById` | `prepareQueryById` → `postProcessGetById` |

---

## 4. Naming & Layering Conventions

| Item | Convention | Example |
|---|---|---|
| Controller folder/file | `<module>Controller/<module>Controller.controller.ts` | `productController/productController.controller.ts` |
| Service folder/file | `<module>Service/<module>Service.service.ts` (default export) | `productService/productService.service.ts` |
| Entity | `src/entities/<module>Entity.ts`, extends `Y0Entity` | `ProductEntity` → table `product_tbl` |
| Model | `repository/<module>/<module>.model.ts`, extends `Y0Model`; **every field must have an initializer** (used by `sanitizeBody` via `hasOwnProperty`) | `name: string = null` |
| DTO | `repository/<module>/<module>.dto.ts`, class-validator decorators | `@IsNotEmpty() name` |
| Route prefix | Add to `APP_ROUTES` enum | `PRODUCT = '/product'` |
| Registration | Add `new XController(APP_ROUTES.X)` in `src/index.ts` | |
| Tests | `__tests__/<module>.<topic>.test.ts` beside the code | |
| Soft delete | `is_delete smallint` (0 / 1) on every table | |
| Error codes | Generic `E10xxx`, domain `E30xxx`; services `reject('E10075')` | |

---

## 5. Base Code Files (copy-ready)

> These are the current base files. Imports that pointed to workflow-engine code **not present in this template**
> (`engine/`, `queue/`, `nodes/`, `utils/natsStream`, etc.) are removed so the files compile in a fresh project.
> Lines marked `// ⚠ B-xx` have a known issue — see [Section 9](#9-bottlenecks--issues-in-the-current-code).

### 5.1 `package.json` (trimmed to what the template uses)

```json
{
  "name": "my-service",
  "version": "1.0.0",
  "main": "build/index.js",
  "scripts": {
    "test": "vitest run",
    "dev": "cross-env NODE_ENV=development ts-node src/index.ts",
    "dev:watch": "cross-env NODE_ENV=development nodemon src/index.ts",
    "build": "tsc",
    "start:dev": "cross-env NODE_ENV=development node build/index.js",
    "start:uat": "cross-env NODE_ENV=uat node build/index.js",
    "start:beta": "cross-env NODE_ENV=beta node build/index.js",
    "start:prod": "cross-env NODE_ENV=production node build/index.js",
    "lint": "eslint . --ext .ts"
  },
  "dependencies": {
    "aws-sdk": "^2.1693.0",
    "bcryptjs": "^3.0.3",
    "class-transformer": "^0.5.1",
    "class-validator": "^0.15.1",
    "cors": "^2.8.6",
    "dotenv": "^17.4.2",
    "express": "^5.2.1",
    "helmet": "^8.1.0",
    "jsonwebtoken": "^9.0.3",
    "multer": "^2.1.1",
    "nodemailer": "^8.0.5",
    "pg": "^8.20.0",
    "reflect-metadata": "^0.2.2",
    "swagger-ui-express": "^5.0.1",
    "tweetnacl": "^1.0.3",
    "typeorm": "^0.3.28"
  },
  "devDependencies": {
    "@types/cors": "^2.8.19",
    "@types/jsonwebtoken": "^9.0.10",
    "@types/multer": "^2.1.0",
    "@types/node": "^25.6.0",
    "@types/nodemailer": "^8.0.0",
    "@types/supertest": "^7.2.0",
    "@types/swagger-ui-express": "^4.1.8",
    "cross-env": "^7.0.3",
    "nodemon": "^3.1.14",
    "supertest": "^7.2.2",
    "ts-node": "^10.9.2",
    "typescript": "^5.9.3",
    "vitest": "^4.1.8"
  }
}
```

> Current repo uses `set NODE_ENV=...&&` (Windows-only) — `cross-env` makes scripts portable (see B-21).

### 5.2 `tsconfig.json`

```jsonc
{
  "compilerOptions": {
    "target": "es2020",
    "lib": ["ES2021"],
    "module": "commonjs",
    "moduleResolution": "node",
    "rootDir": "src",
    "outDir": "build",
    "experimentalDecorators": true,
    "emitDecoratorMetadata": true,        // added: needed by TypeORM / class-transformer (B-24)
    "esModuleInterop": true,
    "allowSyntheticDefaultImports": true,
    "resolveJsonModule": true,
    "forceConsistentCasingInFileNames": true,
    "strict": true,
    "noImplicitAny": false,               // current setting; tighten over time (B-24)
    "strictNullChecks": false,            // current setting; tighten over time (B-24)
    "strictPropertyInitialization": false,
    "skipLibCheck": true
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "build", "src/**/*.test.ts", "src/**/__tests__/**"]
}
```

### 5.3 `nodemon.json`

```json
{
  "signal": "SIGTERM",
  "env": { "NODE_ENV": "development" },
  "ext": "ts,json",
  "watch": ["src"],
  "exec": "ts-node src/index.ts",
  "legacyWatch": true,
  "ignore": ["node_modules", "dist", "build"]
}
```

### 5.4 `src/config.ts`

```ts
import dotenv from "dotenv";

export enum ENV {
  DEVELOPMENT = "development",
  PRODUCTION = "production",
  UAT = "uat",
  BETA = "beta",
}

// Load the right env file first
const nodeEnv = (process.env.NODE_ENV ?? ENV.DEVELOPMENT).trim().toLowerCase();
const envFile =
  nodeEnv === ENV.DEVELOPMENT ? ".env.dev"
  : nodeEnv === ENV.UAT ? ".env.uat"
  : nodeEnv === ENV.BETA ? ".env.beta"
  : ".env.prod";

dotenv.config({ path: envFile });
console.log(`Loaded environment variables from ${envFile} for ${nodeEnv} environment`);

export const NodeEnvironment = nodeEnv;

export const ENABLE_ENCRYPTION: boolean = false;
export const PATH = "/my-service/api/v1";                 // ← change per project
export const PORT = process.env.WF_PORT!;                 // ← rename env var per project
export const NON_ENCRYPTION_ENDPOINTS: string[] = [
  `${PATH}/security/encryption`,
  `${PATH}/security/decryption`,
  `${PATH}/security/saltencryption`,
];

// Auth
export const JWT_SECRET_KEY = process.env.JWT_SECRET_KEY!;
export const JWT_EXPIRES_IN = "3h";
export const REFRESH_JWT_EXPIRES_IN = "5h";
export const ENCRYPTION_SECRET_KEY = process.env.NACL_SECRET_KEY; // base64, 32 bytes
export const SALT_ROUNDS = 10;

// Database
export const DB_WRITE_HOST = process.env.DB_WRITE_HOST!;
export const DB_READ_HOST = process.env.DB_READ_HOST!;
export const DB_USERNAME = process.env.DB_USERNAME!;
export const DB_PASSWORD = process.env.DB_PASSWORD!;
export const DB_NAME = process.env.DB_NAME!;
export const DB_PORT = Number(process.env.DB_PORT!);

// AWS
export const AWS_SECRET_REGION = process.env.AWS_SECRET_REGION || "ap-south-1";
export const AWS_ACCESS_KEY = process.env.AWS_ACCESS_KEY!;
export const AWS_SECRET_KEY = process.env.AWS_SECRET_KEY!;
export const AWS_BUCKET_NAME = process.env.AWS_BUCKET_NAME!;
export const AWS_LOCATION = process.env.AWS_LOCATION!;
export const AWS_ENDPOINT_URL = process.env.AWS_ENDPOINT_URL!;
export const AWS_S3_FOLDER_NAME = "uploads";
export const AWS_SIGNED_URL_EXPIRY = 60 * 5;

// Email
export const SMTP_HOST = process.env.SMTP_HOST!;
export const SMTP_PORT = Number(process.env.SMTP_PORT!) || 587;
export const SMTP_USER = process.env.SMTP_USER!;
export const SMTP_PASSWORD = process.env.SMTP_PASSWORD!;
export const FROM_ADDRESS = process.env.FROM_ADDRESS!;
export const BCC = [];

export enum StatusCode {
  SUCCESS = "10000",
  FAILURE = "10001",
  RETRY = "10002",
  INVALID_ACCESS_TOKEN = "10003",
  INVALID_ENCRYPTED_INPUT = "10004",
}

export enum ResponseStatus {
  SUCCESS = 200,
  CREATED = 201,
  BAD_REQUEST = 400,
  UNAUTHORIZED = 401,
  FORBIDDEN = 403,
  NOT_FOUND = 404,
  METHOD_NOT_FOUND = 405,
  INTERNAL_ERROR = 500,
}
```

`.env.dev` keys: `WF_PORT, JWT_SECRET_KEY, NACL_SECRET_KEY, DB_WRITE_HOST, DB_READ_HOST, DB_USERNAME, DB_PASSWORD, DB_NAME, DB_PORT, AWS_*, SMTP_*, FROM_ADDRESS`.

### 5.5 `src/index.ts`

```ts
import 'reflect-metadata';                     // added: required once for TypeORM decorators (B-24)
import { App } from './app';
import { PORT } from './config';
import { APP_ROUTES } from './core/AppRoutes';
import { APIHealthCheckController } from './controllers/apiHealthController/apiHealthController.controller';

(async function () {
    try {
        const app = new App([
            new APIHealthCheckController(APP_ROUTES.APIHEALTHCHECK),
            // new ProductController(APP_ROUTES.PRODUCT),   ← register new modules here
        ], PORT);
        app.listen();
    } catch (error) {
        console.error('Error initializing the app:', error);
    }
})();
```

### 5.6 `src/app.ts`

```ts
import express from 'express';
import multer from 'multer';
import helmet from 'helmet';
import cors from 'cors';
import { ENABLE_ENCRYPTION, NON_ENCRYPTION_ENDPOINTS, PATH, StatusCode } from './config';
import Database from './databases/database';
import { EncryptionAndDecryption } from './core/Encryption&Decryption';
import { ApiError, BadRequestError, MethodNotFoundError, NotFoundError } from './core/ApiError';
import { BaseController } from './controllers/baseController';
import { setupSwagger } from './swagger';

export class App {
    public app: express.Application;
    public port: any;
    private pathList: any[] = [];
    private database = Database.getInstance();

    constructor(controllers: BaseController[], port: any) {
        this.app = express();
        this.port = port;
        this.bootstrap();                              // ⚠ B-06 not awaited
        this.initializeMiddlewares();
        this.initializeControllers(controllers);
        setupSwagger(this.app);
        this.initializeErrorHandling();
    }

    private initializeDatabase(): Promise<void> {
        return this.database.connectToDB();
    }

    private initializeMiddlewares() {
        this.app.use(express.json({ limit: '15mb' }));
        this.app.use(express.urlencoded({ extended: true }));
        this.app.use(multer({ limits: { fileSize: 250 * 1024 * 1024 } }).any());   // ⚠ B-07
        this.app.use(cors());
        this.app.use(helmet());

        // Optional request-body decryption
        this.app.use((req, res, next): any => {
            if (ENABLE_ENCRYPTION && !NON_ENCRYPTION_ENDPOINTS.includes(req.url) && req.method === 'POST') {
                let result = null;
                if (req.url.includes('/getall') || req.url.includes('/getdata')) {
                    if (req.body.details !== undefined) {
                        result = EncryptionAndDecryption.decryption(req.body.details);
                        if (result === StatusCode.INVALID_ENCRYPTED_INPUT) {
                            return ApiError.handle(new BadRequestError('Invalid Encrypted String'), res);
                        }
                        req.body = result;
                    }
                } else {
                    result = EncryptionAndDecryption.decryption(req.body.details);
                    if (result === StatusCode.INVALID_ENCRYPTED_INPUT) {
                        return ApiError.handle(new BadRequestError('Invalid Encrypted String'), res);
                    }
                    req.body = result;
                }
            }
            next();
        });
    }

    private initializeControllers(controllers: BaseController[]) {
        controllers.forEach((controller) => {
            controller.router.stack.forEach((stack: any) => {
                this.pathList.push({
                    path: PATH + stack.route.path,
                    method: `${stack.route.stack[0].method}`.toLocaleUpperCase(),
                });
            });
            this.app.use(PATH, controller.router);
        });
    }

    private initializeErrorHandling() {
        // 405 / 404 fallback                                          ⚠ B-14
        this.app.use((req, res, _next): any => {
            for (const val of this.pathList) {
                if (req.path === val.path && req.method !== val.method) {
                    return ApiError.handle(new MethodNotFoundError(), res);
                }
            }
            return ApiError.handle(new NotFoundError(), res);
        });
    }

    private async bootstrap(): Promise<void> {
        try {
            await this.initializeDatabase();
            console.log('[App] Bootstrap complete — DB connected');
        } catch (error) {
            console.error('[App] Fatal bootstrap error:', error);
            process.exit(1);
        }
    }

    public listen() {
        this.app.listen(this.port, () => console.log(`App listening on the port ${this.port}`));
    }
}
```

### 5.7 `src/databases/dataSource.ts`

```ts
import { DataSource } from 'typeorm';
import { DB_NAME, DB_PASSWORD, DB_PORT, DB_READ_HOST, DB_USERNAME, DB_WRITE_HOST } from '../config';
// import { ProductEntity } from '../entities/productEntity';   ← import every entity

export const getPostgresConnection = () => {
    return new DataSource({
        name: 'default',
        type: 'postgres',
        replication: {
            master: { host: DB_WRITE_HOST, port: DB_PORT, username: DB_USERNAME, password: DB_PASSWORD, database: DB_NAME },
            slaves: [{ host: DB_READ_HOST, port: DB_PORT, username: DB_USERNAME, password: DB_PASSWORD, database: DB_NAME }],
        },
        entities: [/* ProductEntity, ... */],          // ⚠ B-04 must list entities
        synchronize: false,
        logging: false,
        ssl: true,
        extra: {
            ssl: { rejectUnauthorized: false },        // ⚠ B-19
            max: 20,
            min: 5,
            idleTimeoutMillis: 30000,
            connectionTimeoutMillis: 10000,
            keepAlive: true,
        },
    });
};
```

### 5.8 `src/databases/database.ts`

```ts
import { DataSource, EntityManager } from 'typeorm';
import { getPostgresConnection } from './dataSource';
import { DB_USERNAME } from '../config';

class AppDatabase {
    private static instance: AppDatabase;
    private postgresConnection: DataSource | null = null;
    private entityManager: EntityManager | null = null;

    static getInstance(): AppDatabase {
        if (!AppDatabase.instance) AppDatabase.instance = new AppDatabase();
        return AppDatabase.instance;
    }

    async connectToDB(): Promise<void> {
        if (!this.postgresConnection) {
            this.postgresConnection = getPostgresConnection();
            await this.postgresConnection.initialize();
            this.entityManager = this.postgresConnection.manager;
            console.log(`Connected to Postgres DB with user ${DB_USERNAME}`);
        }
    }

    public async executeExternalQuery(query: string, params: any[] = []): Promise<any> {
        if (!this.entityManager) throw new Error('Database connection not established!');
        return this.entityManager.query(query, params);
    }

    public async executeInTransaction<T>(callback: (manager: EntityManager) => Promise<T>): Promise<T> {
        if (!this.postgresConnection) throw new Error('Database connection not established!');
        return this.postgresConnection.transaction(callback);
    }
}

export default AppDatabase;
```

### 5.9 `src/entities/y0Entity.ts` — base entity

```ts
import { BaseEntity, Column, Entity, PrimaryGeneratedColumn, CreateDateColumn, UpdateDateColumn } from 'typeorm';

@Entity('y0_tbl')
export class Y0Entity extends BaseEntity {
    @PrimaryGeneratedColumn({ type: 'integer' })
    id: number;

    @CreateDateColumn({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
    created_at: Date;

    @UpdateDateColumn({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP', onUpdate: 'CURRENT_TIMESTAMP' })
    modified_at: Date;

    @Column({ type: 'smallint', default: 0 })
    is_delete: number;
}
```

### 5.10 `src/databases/repository/y0Model/y0Model.model.ts` — base model

```ts
export class Y0Model {
    id: number = null;
}
```

### 5.11 `src/core/Y0Params.ts` (generic part)

```ts
export class Y0Params {
    id: number = null;
}

export class Filter extends Y0Params {
    search?: string = '';
    year?: string = '';
    startDate?: string = '';
    endDate?: string = '';
    isActive?: boolean = null;
    status?: string = null;
}

export class Pagination extends Y0Params {
    pageSize: number = 25;
    pageNumber: number = 0;
    filter: Filter = { id: null, search: '', year: '' };
    sortBy: string = null;
    sortType: string = null;
}
// Project-specific param classes (NodeConfigurationFilter, WorkspaceFoldersParams, CredentialParams …) go below.
```

### 5.12 `src/core/MetaModel.ts` & `src/core/FileModel.ts`

```ts
// MetaModel.ts
type fileStructure = {
    fileKey: string;            // multipart field name
    allowedSize: number;        // bytes
    allowedExtensions: string[];// mime types
    colName: string;            // DB column storing the file name
    require: string;            // "true" | "false"
};

export class MetaModel {
    modelName: string;          // S3 folder: <AWS_S3_FOLDER_NAME>/<modelName>/<id>/<file>
    fileFieldName: string;
    files: fileStructure[];

    constructor(name: string, fieldName: string, files: fileStructure[]) {
        this.modelName = name;
        this.fileFieldName = fieldName;
        this.files = files;
    }
}
```

```ts
// FileModel.ts
export interface FileObject {
    fieldname: string;
    originalname: string;
    encoding: string;
    mimetype: string;
    buffer: ArrayBuffer;
    size: number;
}
export interface UploadedFile { path: string; }
```

### 5.13 `src/core/AppRoutes.ts`

```ts
export enum APP_ROUTES {
    APIHEALTHCHECK = '/apiHealthCheck',
    // PRODUCT = '/product',
}

export enum SUCCESSMSG {
    GET = `Fetched Successfully`,
    ADD = `Added Successfully`,
    UPDATE = `Updated Successfully`,
    DELETE = `Deleted Successfully`,
}
```

### 5.14 `src/core/GenericResponse.ts`

```ts
export class GenericResponse<T> {
    private status: string;
    private error: string;
    private details: T;
    private msg: string;
    private totalRecords: number;

    public getStatus(): string { return this.status; }
    public setStatus(status: string): void { this.status = status; }
    public getError(): string { return this.error; }
    public setError(error: string): void { this.error = error; }
    public getData(): T { return this.details; }
    public setData(data: T): void { this.details = data; }
    public getMsg(): string { return this.msg; }
    public setMsg(msg: string): void { this.msg = msg; }
    public setEncryptedData(details: T): void { this.details = details; }
    public getTotalRecords(): number { return this.totalRecords; }
    public setTotalRecords(totalRecord: number): void { this.totalRecords = totalRecord; }
}
```

### 5.15 `src/core/ApiResponse.ts`

```ts
import { Response } from 'express';
import { ENABLE_ENCRYPTION, ResponseStatus, StatusCode } from '../config';
import { EncryptionAndDecryption } from './Encryption&Decryption';

abstract class ApiResponse {
    constructor(protected statusCode: StatusCode, protected status: ResponseStatus, protected message: string) { }

    protected prepare<T extends ApiResponse>(res: Response, response: T): Response {
        const clientResponse = ApiResponse.sanitize(response, res.req.url);
        return res.status(this.status).json(clientResponse);
    }

    public send(res: Response): Response {
        return this.prepare<ApiResponse>(res, this);
    }

    private static sanitize<T extends ApiResponse>(response: T, url: string): T {
        const clone: T = {} as T;
        Object.assign(clone, response);
        // @ts-ignore
        delete clone.status;
        for (const i in clone) if (typeof clone[i] === 'undefined') delete clone[i];
        // @ts-ignore
        if (ENABLE_ENCRYPTION === true && clone['data'] && !url.includes('/security/')) {
            // @ts-ignore
            clone['data'] = EncryptionAndDecryption.encryption(clone['data']);
        }
        return clone;
    }
}

export class AuthFailureResponse extends ApiResponse {
    constructor(message = 'Authentication Failure') { super(StatusCode.FAILURE, ResponseStatus.UNAUTHORIZED, message); }
}
export class NotFoundResponse extends ApiResponse {
    private url: string | undefined;
    constructor(message = 'Not Found') { super(StatusCode.FAILURE, ResponseStatus.NOT_FOUND, message); }
    send(res: Response): Response { this.url = res.req?.originalUrl; return super.prepare<NotFoundResponse>(res, this); }
}
export class MethodNotFoundResponse extends ApiResponse {
    private url: string | undefined;
    constructor(message = 'Method Not Found') { super(StatusCode.FAILURE, ResponseStatus.METHOD_NOT_FOUND, message); }
    send(res: Response): Response { this.url = res.req?.originalUrl; return super.prepare<MethodNotFoundResponse>(res, this); }
}
export class ForbiddenResponse extends ApiResponse {
    constructor(message = 'Forbidden') { super(StatusCode.FAILURE, ResponseStatus.FORBIDDEN, message); }
}
export class BadRequestResponse extends ApiResponse {
    constructor(message = 'Bad Parameters') { super(StatusCode.FAILURE, ResponseStatus.BAD_REQUEST, message); }
}
export class BadRequestResponseWithDetailMsg extends ApiResponse {
    constructor(message = 'Bad Parameters', private detailMsg: any[] = []) { super(StatusCode.FAILURE, ResponseStatus.BAD_REQUEST, message); }
}
export class InternalErrorResponse extends ApiResponse {
    constructor(message = 'Internal Error') { super(StatusCode.FAILURE, ResponseStatus.INTERNAL_ERROR, message); }
}
export class SuccessMsgResponse extends ApiResponse {
    constructor(message: string) { super(StatusCode.SUCCESS, ResponseStatus.SUCCESS, message); }
}
export class FailureMsgResponse<T> extends ApiResponse {
    constructor(message: string) { super(StatusCode.FAILURE, ResponseStatus.SUCCESS, message); }
}
export class SuccessResponse<T> extends ApiResponse {
    constructor(message: string, private data: T) { super(StatusCode.SUCCESS, ResponseStatus.SUCCESS, message); }
}
export class AccessTokenErrorResponse extends ApiResponse {
    private instruction = 'refresh_token';
    constructor(message = 'Access token invalid') { super(StatusCode.INVALID_ACCESS_TOKEN, ResponseStatus.UNAUTHORIZED, message); }
    send(res: Response): Response { res.setHeader('instruction', this.instruction); return super.prepare<AccessTokenErrorResponse>(res, this); }
}
export class TokenRefreshResponse extends ApiResponse {
    constructor(message: string, private accessToken: string, private refreshToken: string) { super(StatusCode.SUCCESS, ResponseStatus.SUCCESS, message); }
}
```

### 5.16 `src/core/ApiError.ts`

```ts
import { Response } from 'express';
import {
    AuthFailureResponse, AccessTokenErrorResponse, InternalErrorResponse, NotFoundResponse,
    BadRequestResponse, ForbiddenResponse, FailureMsgResponse, MethodNotFoundResponse,
} from './ApiResponse';

export enum ErrorType {
    BAD_TOKEN = 'BadTokenError',
    TOKEN_EXPIRED = 'TokenExpiredError',
    UNAUTHORIZED = 'AuthFailureError',
    ACCESS_TOKEN = 'AccessTokenError',
    INTERNAL = 'InternalError',
    NOT_FOUND = 'NotFoundError',
    METHOD_NOT_FOUND = 'MethodNotFoundError',
    NO_ENTRY = 'NoEntryError',
    NO_DATA = 'NoDataError',
    BAD_REQUEST = 'BadRequestError',
    FORBIDDEN = 'ForbiddenError',
    DB_ERROR = 'DBError',
    CORS_ERROR = 'CorsError',
}

export abstract class ApiError extends Error {
    constructor(public type: ErrorType, public message: string = 'error') {
        super(type);
    }

    public static handle(err: ApiError, res: Response): Response {
        switch (err.type) {
            case ErrorType.BAD_TOKEN:
            case ErrorType.TOKEN_EXPIRED:
            case ErrorType.UNAUTHORIZED:     return new AuthFailureResponse(err.message).send(res);
            case ErrorType.ACCESS_TOKEN:     return new AccessTokenErrorResponse(err.message).send(res);
            case ErrorType.INTERNAL:         return new InternalErrorResponse(err.message).send(res);
            case ErrorType.NOT_FOUND:
            case ErrorType.NO_ENTRY:
            case ErrorType.NO_DATA:          return new NotFoundResponse(err.message).send(res);
            case ErrorType.METHOD_NOT_FOUND: return new MethodNotFoundResponse(err.message).send(res);
            case ErrorType.BAD_REQUEST:      return new BadRequestResponse(err.message).send(res);
            case ErrorType.FORBIDDEN:        return new ForbiddenResponse(err.message).send(res);
            case ErrorType.DB_ERROR:         return new FailureMsgResponse(err.message).send(res);
            default: {
                const error: any = err;
                if (error.code === '23503') {
                    return new FailureMsgResponse('Violation of foreign constraint, ' + error.detail).send(res);
                }
                if (error.code === '23505') {   // ⚠ B-27
                    return new FailureMsgResponse(error.detail.split('Key')[1].split('(').join(' ').split(')').join(' ')).send(res);
                }
                console.log(error);
                return new InternalErrorResponse(err.message).send(res);
            }
        }
    }
}

export class CorsError extends ApiError { constructor(message: any = 'Not Allowed By CORS') { super(ErrorType.CORS_ERROR, message); } }
export class AuthFailureError extends ApiError { constructor(message = 'Invalid Credentials') { super(ErrorType.UNAUTHORIZED, message); } }
export class InternalError extends ApiError { constructor(message = 'Internal error') { super(ErrorType.INTERNAL, message); } }
export class BadRequestError extends ApiError { constructor(message: any = 'Bad Request') { super(ErrorType.BAD_REQUEST, message); } }
export class NotFoundError extends ApiError { constructor(message = 'Not Found') { super(ErrorType.NOT_FOUND, message); } }
export class MethodNotFoundError extends ApiError { constructor(message = 'Method Not Found') { super(ErrorType.METHOD_NOT_FOUND, message); } }
export class ForbiddenError extends ApiError { constructor(message = 'Permission denied') { super(ErrorType.FORBIDDEN, message); } }
export class NoEntryError extends ApiError { constructor(message = "Entry don't exists") { super(ErrorType.NO_ENTRY, message); } }
export class BadTokenError extends ApiError { constructor(message = 'Invalid Token') { super(ErrorType.BAD_TOKEN, message); } }
export class TokenExpiredError extends ApiError { constructor(message = 'Token is expired') { super(ErrorType.TOKEN_EXPIRED, message); } }
export class NoDataError extends ApiError { constructor(message = 'No data available') { super(ErrorType.NO_DATA, message); } }
export class AccessTokenError extends ApiError { constructor(message = 'Invalid access token') { super(ErrorType.ACCESS_TOKEN, message); } }
export class DBValidationError extends ApiError { constructor(message = 'Invalid inputs') { super(ErrorType.DB_ERROR, message); } }
```

### 5.17 `src/core/ErrorCodes.ts` (shape — full file has ~78 codes)

```ts
export const ErrorCodes = {
    E10001: { type: 'generic', message: 'The requested resource was not found.', status: 404 },
    E10002: { type: 'generic', message: 'You are not authorized to perform this action.', status: 401 },
    E10003: { type: 'generic', message: 'Access to this resource is forbidden.', status: 403 },
    E10004: { type: 'generic', message: 'The data provided did not pass validation.', status: 400 },
    E10005: { type: 'generic', message: 'An unexpected error occurred on the server.', status: 500 }, // default fallback
    E10006: { type: 'generic', message: 'The request could not be understood by the server.', status: 400 },
    E10007: { type: 'generic', message: 'There is a conflict with the current state of the resource.', status: 409 },
    E10008: { type: 'generic', message: 'This feature is not implemented yet.', status: 501 },
    E10009: { /* service unavailable – used by worker health */ },
    E10072: { /* soft-delete failed */ },
    E10073: { /* invalid / missing id */ },
    E10075: { /* record not found (findEntity) */ },
    // E30xxx: domain-specific codes
};
```

### 5.18 Middlewares

**`src/middlewares/auth.middleware.ts`**

```ts
import express from 'express';
import { ApiError, BadTokenError } from '../core/ApiError';
import { UserLoginsEntity } from '../entities/userLoginsEntity';   // ← provide this entity in your project
import { isTokenValid, verifyjwt } from '../utils/jwt/jwt';

const authMiddleware = async (req: express.Request, res: express.Response, next: express.NextFunction): Promise<any> => {
    try {
        if (!req.headers.authorization || !req.headers.authorization.startsWith('Bearer ')) {
            return ApiError.handle(new BadTokenError('Token is missing or invalid'), res);
        }
        const token = req.headers.authorization.split(' ')[1];
        const decryptToken: any = verifyjwt(token);

        const loginUserdetail = await UserLoginsEntity.findOneBy({     // ⚠ B-08 DB hit per request
            userid: decryptToken.user_id,
            access_token: token,
            is_delete: 0,
        });
        if (!loginUserdetail) {
            return ApiError.handle(new BadTokenError('Unauthorized access'), res);
        }

        const isNotExp = await isTokenValid(decryptToken);              // ⚠ B-08 check before DB
        if (!isNotExp) {
            return ApiError.handle(new BadTokenError('Token has expired. Please login again'), res);
        }

        req.body = { ...req.body, ...decryptToken };                    // token claims merged into body
        next();
    } catch (err) {
        console.log('authMiddleware error', err);
        return ApiError.handle(new BadTokenError('Authentication failed! Please try again'), res);
    }
};

export default authMiddleware;
```

**`src/middlewares/sanitizeBody.middleware.ts`**

```ts
/** Remove keys from body that are not own properties of the Model instance. */
const sanitizeBody = (classModel: any, body: any) => {
    Object.keys(body).forEach((key) => {
        if (!classModel.hasOwnProperty(key)) delete body[key];
    });
    return body;
};
export default sanitizeBody;
```

**`src/middlewares/sanitizeFile.middleware.ts`**

```ts
import { MetaModel } from '../core/MetaModel';

/** Keep only uploaded files whose field name is declared in MetaModel. */
const sanitizeFile = (metaModel: MetaModel, files: any) => {
    const result = [];
    const keys = metaModel.files.map((file) => file.fileKey);
    for (const f of files) if (keys.includes(f.fieldname)) result.push(f);
    return result;
};
export default sanitizeFile;
```

**`src/middlewares/validationFormData.middleware.ts`**

```ts
import { plainToInstance } from 'class-transformer';
import { validate, ValidationError } from 'class-validator';
import { RequestHandler } from 'express';
import { BadRequestResponseWithDetailMsg } from '../core/ApiResponse';
import { MetaModel } from '../core/MetaModel';

function validationFDMiddleware<T>(type: any, metaModel: MetaModel, skipMissingProperties = false): RequestHandler {
    return (req, res, next) => {
        const validFiles = req.files && (req.files as any[]).length !== 0 ? sanitizeFile(metaModel, req.files) : null;
        validFiles !== null ? (type.files = validFiles) : null;          // ⚠ B-12 mutates shared class
        const ptc: any = plainToInstance(type, req.body);
        ptc.files = validFiles;
        validate(ptc, { skipMissingProperties }).then((errors: ValidationError[]) => {
            if (errors.length > 0) {
                let fields = '';
                const detailMsg = errors.map((error) => {
                    fields += error.property + ', ';
                    const errorMessage = Object.values(error.constraints).join('. ');   // ⚠ B-12
                    return `${error.property}: ${errorMessage}`;
                });
                const message = `Please fill ${fields}fields properly: ${detailMsg.join('\n')}`;
                return new BadRequestResponseWithDetailMsg(message, null).send(res);
            }
            next();
        });
    };
}

/** Pairs every MetaModel file rule with the uploaded file (or undefined) for FileExistsValidator. */
const sanitizeFile = (metaModel: MetaModel, files: any) => {
    const out = [];
    for (const rule of metaModel.files) {
        const opts = { allowedSize: rule.allowedSize, require: rule.require, allowedExtensions: rule.allowedExtensions };
        const matches = files.filter((f) => f.fieldname === rule.fileKey);
        if (matches.length === 0) out.push({ file: undefined, fileExistsValidatorOptions: opts });
        else matches.forEach((f) => out.push({ file: f, fileExistsValidatorOptions: opts }));
    }
    return out;
};

export default validationFDMiddleware;
```

### 5.19 Utilities

**`src/utils/jwt/jwt.ts`**

```ts
import jwt from 'jsonwebtoken';
import { JWT_SECRET_KEY, JWT_EXPIRES_IN, REFRESH_JWT_EXPIRES_IN } from '../../config';

export const createjwt = (body: any) => jwt.sign(body, JWT_SECRET_KEY, { expiresIn: JWT_EXPIRES_IN });
export const verifyjwt = (token: string) => jwt.verify(token, JWT_SECRET_KEY, { ignoreExpiration: true }); // ⚠ B-08
export const refreshjwt = (body: any) => jwt.sign(body, JWT_SECRET_KEY, { expiresIn: REFRESH_JWT_EXPIRES_IN });

export const isTokenValid = async (token: { exp?: number }): Promise<boolean> => {
    const now = Math.floor(Date.now() / 1000);
    return typeof token.exp === 'number' && token.exp > now;
};
```

**`src/core/Encryption&Decryption.ts`** — copy as is. Public API:

| Method | Purpose |
|---|---|
| `encryption(body)` | JSON → NaCl secretbox (nonce + cipher) → base64 |
| `decryption(str)` | base64 → object, or `StatusCode.INVALID_ENCRYPTED_INPUT` |
| `encryptionIds / decryptionIds` | URL-safe base64 variants |
| `saltEncryption / saltCompare` | bcrypt hash / compare (`SALT_ROUNDS`) |

**`src/core/AwsService.ts`** — copy as is. Public API: `upload(files, modelName, id)`, `generateSignedUrl(key, fileName?, expireIn?, isDownload?)`,
`getObjectStream(key)`, `deleteFiles(paths)`, `deleteImageByUrl(url)`, `getMedia(paths)`, `uploadErrorFile(...)`,
`uploadFromBuffer(...)`, and `getSecretKey(secretName)` for AWS Secrets Manager. S3 key format:
`<AWS_S3_FOLDER_NAME>/<modelName>/<id>/<originalname with spaces→'-'>`.

**`src/utils/email/EmailService.ts`** — `EmailService.sendEmail({ email, subject, text?, html?, cc?, headers? })` (see B-18).

### 5.20 `src/controllers/baseController.ts` ★

```ts
import express from 'express';
import { APP_ROUTES, SUCCESSMSG } from '../core/AppRoutes';
import validationFDMiddleware from '../middlewares/validationFormData.middleware';
import { ENABLE_ENCRYPTION, ResponseStatus, StatusCode } from '../config';
import sanitizeBody from '../middlewares/sanitizeBody.middleware';
import sanitizeFile from '../middlewares/sanitizeFile.middleware';
import { MetaModel } from '../core/MetaModel';
import { ErrorCodes } from '../core/ErrorCodes';
import { GenericResponse } from '../core/GenericResponse';
import { FileObject } from '../core/FileModel';
import { EncryptionAndDecryption } from '../core/Encryption&Decryption';
import { BaseServices } from '../services/baseService';
import authMiddleware from '../middlewares/auth.middleware';
import { Pagination, Y0Params } from '../core/Y0Params';
import { Y0Model } from '../databases/repository/y0Model/y0Model.model';

export abstract class BaseController {
    dto: any;
    constructor(protected path: APP_ROUTES, public router = express.Router(), public service: BaseServices) {
        this.dto = this.service.getDTO();
        this._initialiseRoutes();
    }

    /** Override in a module to expose a different / smaller set of routes. */
    public _initialiseRoutes(): void {
        this.router.post(`${this.path}/getall`, authMiddleware, this.getAll.bind(this));
        this.router.get(`${this.path}/getbyid/:id`, authMiddleware, this.getById.bind(this));
        this.router.delete(`${this.path}/delete/:id`, authMiddleware, this.deleteData.bind(this));
        this.router.post(`${this.path}/save`, authMiddleware, validationFDMiddleware(this.dto, this.service.getMetaModel()), this.postData.bind(this));
        this.router.post(`${this.path}/updateDeleteFlagData`, authMiddleware, this.updateDeleteFlagData.bind(this));
        this.router.post(`${this.path}/savemulti`, authMiddleware, validationFDMiddleware(this.dto, this.service.getMetaModel()), this.postMultiData.bind(this));
        this.router.post(`${this.path}/getdata`, authMiddleware, this.getData.bind(this));
        this.router.post(`${this.path}/getdatabyid`, authMiddleware, this.getDataById.bind(this));
    }

    public prepareParams(param: Pagination, req: express.Request) {
        param.pageNumber = req.body.pageNumber ?? 0;
        param.pageSize = req.body.pageSize ?? 25;                       // ⚠ B-09 unbounded
        param.filter.search = req.body.search ? req.body.search.trim() : '';
        return param;
    }

    protected getAll(req: express.Request, res: express.Response, _next: express.NextFunction) {
        const msg = this.handleSuccessMessage('GET', req);
        const params = this.prepareParams(new Pagination(), req);
        this.service.getAll(params)
            .then((data) => this.sendResponse(StatusCode.SUCCESS, msg, data.records, data.totalRecords, null, res, ResponseStatus.SUCCESS))
            .catch((err) => this.handleError(err, res));
    }

    protected setParamsForData(req: express.Request): Y0Params {
        const param = new Y0Params();
        param.id = +req.params.id;
        return param;
    }

    protected getById(req: express.Request, res: express.Response, _next: express.NextFunction) {
        const params = this.setParamsForData(req);
        const msg = this.handleSuccessMessage('GETBYID', req);
        if (this.validateData(params)) {
            this.service.getById(params)
                .then((data) => this.sendResponse(StatusCode.SUCCESS, msg, data, 0, null, res, ResponseStatus.SUCCESS))
                .catch((err) => this.handleError(err, res));
        } else {
            this.handleError(null, res);
        }
    }

    validateData(param: Y0Params): boolean {
        return param.id !== null;                                       // ⚠ B-15 NaN passes
    }

    protected async postData(req: express.Request, res: express.Response, _next: express.NextFunction) {
        const model = this.service.getModel();
        const msg = this.handleSuccessMessage('POST', req);
        const data = this.processData(req, model);
        const validFiles: FileObject[] = req.files && (req.files as any[]).length !== 0 ? this.processFileData(req, this.service.getMetaModel()) : null;
        this.service.createRecord(data, validFiles)
            .then((data) => this.sendResponse(StatusCode.SUCCESS, msg, data, 0, null, res, ResponseStatus.SUCCESS))
            .catch((err) => this.handleError(err, res));
    }

    protected async postMultiData(req: express.Request, res: express.Response, _next: express.NextFunction) {
        const model = this.service.getModel();
        const data = this.processData(req, model);
        const msg = this.handleSuccessMessage('POST', req);
        const validFiles: FileObject[] = req.files && (req.files as any[]).length !== 0 ? this.processFileData(req, this.service.getMetaModel()) : null;
        this.service.createMultiRecords(data, validFiles)
            .then((data) => this.sendResponse(StatusCode.SUCCESS, msg, data, 0, null, res, ResponseStatus.SUCCESS))
            .catch((err) => this.handleError(err, res));
    }

    protected deleteData(req: express.Request, res: express.Response, _next: express.NextFunction) {
        const param = new Y0Params();
        const msg = this.handleSuccessMessage('DELETE', req);
        param.id = +req.params.id;
        this.service.deleteData(param)
            .then((response) => response == true
                ? this.sendResponse(StatusCode.SUCCESS, msg, null, 0, null, res, ResponseStatus.SUCCESS)
                : this.handleError('Error while deleting Record', res))
            .catch((err) => this.handleError(err, res));
    }

    public processData(req: express.Request, model: Y0Model): Y0Model {
        return sanitizeBody(model, req.body);
    }

    public processFileData(req: express.Request, metaModel: MetaModel): any {
        return sanitizeFile(metaModel, req.files);
    }

    handleError(errorCode, res) {
        // Structured error { code, message?, meta? }
        if (errorCode && typeof errorCode === 'object' && typeof errorCode.code === 'string') {
            const err = this.getErrorMessage(errorCode.code);
            this.sendResponse(StatusCode.FAILURE, '', errorCode.meta ?? null, 0, errorCode.message ?? err.message, res, err.status);
            return;
        }
        // Bare string code 'E10075' (unknown → E10005)
        const err = this.getErrorMessage(errorCode);
        this.sendResponse(StatusCode.FAILURE, '', null, 0, err.message, res, err.status);
    }

    getErrorMessage(errorCode: string): any {
        return ErrorCodes[errorCode] ? ErrorCodes[errorCode] : ErrorCodes['E10005'];
    }

    getSuccessMsg(moduleName: string, _req: express.Request): string {
        return `${moduleName} ${SUCCESSMSG.GET}`;
    }

    getPostSuccessMsg(moduleName: string, req: express.Request): string {
        return req.body.id ? `${moduleName} ${SUCCESSMSG.UPDATE}` : `${moduleName} ${SUCCESSMSG.ADD}`;
    }

    getDeleteSuccessMsg(moduleName: string, _req: express.Request): string {
        return `${moduleName} ${SUCCESSMSG.DELETE}`;
    }

    handleSuccessMessage(method: string, req: express.Request): string {
        const moduleName = this.service.getModuleName();
        switch (method) {
            case 'GET': return this.getSuccessMsg(moduleName, req);
            case 'POST': return this.getPostSuccessMsg(moduleName, req);
            case 'DELETE': return this.getDeleteSuccessMsg(moduleName, req);
            default: return '';
        }
    }

    public sendResponse(status: string, msg: string, detail: Y0Model, totalRecords: number, error: string, res: express.Response, statusCode: number) {
        const genericResponse = new GenericResponse<Y0Model>();
        genericResponse.setStatus(status);
        genericResponse.setMsg(msg);
        genericResponse.setError(error);
        genericResponse.setData(detail);
        genericResponse.setTotalRecords(totalRecords);
        if (ENABLE_ENCRYPTION === true && !res.req.url.includes('/security/')) {   // ⚠ B-16
            genericResponse.setEncryptedData(EncryptionAndDecryption.encryption(detail));
        }
        res.status(statusCode).send(genericResponse);
    }

    protected updateDeleteFlagData(req: express.Request, res: express.Response, _next: express.NextFunction) {
        const msg = this.handleSuccessMessage('DELETE', req);
        this.service.updateDeleteFlagData(req.body)
            .then((response) => response == true
                ? this.sendResponse(StatusCode.SUCCESS, msg, null, 0, null, res, ResponseStatus.SUCCESS)
                : this.handleError('E10072', res))
            .catch((err) => this.handleError(err, res));
    }

    public prepareQueryParams(_param: Pagination, req: express.Request) {
        return req.body;
    }

    protected getData(req: express.Request, res: express.Response, _next: express.NextFunction) {
        const msg = this.handleSuccessMessage('GET', req);
        const paramData = this.prepareQueryParams(new Pagination(), req);
        this.service.getData(paramData)
            .then((data) => this.sendResponse(StatusCode.SUCCESS, msg, data.records, data.totalRecords, null, res, ResponseStatus.SUCCESS))
            .catch((err) => this.handleError(err, res));
    }

    public prepareQueryParamsById(_param: Pagination, req: express.Request) {
        return req.body;
    }

    protected getDataById(req: express.Request, res: express.Response, _next: express.NextFunction) {
        const msg = this.handleSuccessMessage('GETBYID', req);
        const paramData = this.prepareQueryParamsById(new Pagination(), req);
        this.service.getDataById(paramData)
            .then((data) => this.sendResponse(StatusCode.SUCCESS, msg, data, 0, null, res, ResponseStatus.SUCCESS))
            .catch((err) => this.handleError(err, res));
    }
}
```

### 5.21 `src/services/baseService.ts` ★

```ts
import { AwsService } from '../core/AwsService';
import { FileObject } from '../core/FileModel';
import { MetaModel } from '../core/MetaModel';
import { Brackets, In } from 'typeorm';
import { AWS_S3_FOLDER_NAME } from '../config';
import { Y0Entity } from '../entities/y0Entity';
import { Y0Model } from '../databases/repository/y0Model/y0Model.model';
import { Pagination, Y0Params } from '../core/Y0Params';

export abstract class BaseServices {
    public entity: any;

    protected constructor(entity: Y0Entity, protected awsService: AwsService) {
        this.entity = entity;
    }

    // ── Module contract ─────────────────────────────────────────────
    abstract getModel(): Y0Model;
    abstract getDTO(): any;
    getModuleName(): string { return ''; }
    getMetaModel(): MetaModel { return null; }
    getGolbalSearchColumns(): string[] { return []; }

    // ── getAll ──────────────────────────────────────────────────────
    protected prepareFilter(queryBuilder: any, param: Pagination): any {
        queryBuilder.where('main.is_delete = 0');
        queryBuilder.orderBy('main.created_at', 'DESC');
        if (param.pageNumber > 0) {                                     // ⚠ B-09 0 → no LIMIT
            queryBuilder.skip((param.pageNumber - 1) * param.pageSize).take(param.pageSize);
        }
        return queryBuilder;
    }

    protected applyGlobalSearch(queryBuilder: any, params: Pagination): any {
        const search_text = params.filter.search;
        const columns = this.getGolbalSearchColumns();
        if (search_text && columns.length > 0) {
            queryBuilder.andWhere(new Brackets((qb1) => {
                columns.forEach((col, index) => {
                    const key = `search${index}`;
                    qb1.orWhere(`LOWER(${col}) LIKE :${key}`, { [key]: `%${search_text.toLowerCase()}%` }); // ⚠ B-10
                });
            }));
        }
        return queryBuilder;
    }

    postProcessAfterGetData(result: any, _param: Pagination): Promise<Y0Model> {
        return Promise.resolve(result);
    }

    public getAll = async (param: Pagination): Promise<any> => {
        const queryBuilder = this.entity.createQueryBuilder('main');
        this.prepareFilter(queryBuilder, param);
        this.applyGlobalSearch(queryBuilder, param);
        const [records, totalRecords] = await queryBuilder.getManyAndCount();
        if (records && records.length > 0) {
            return { records: await this.postProcessAfterGetData(records, param), totalRecords };
        }
        return { records, totalRecords };
    };

    // ── getById ─────────────────────────────────────────────────────
    postProcessAfterGetById(result: any): Promise<Y0Model> { return Promise.resolve(result); }

    public getById = async (param: Y0Params): Promise<Y0Model> => {
        const record = await this.findEntity(param.id);
        return this.postProcessAfterGetById(record);
    };

    // ── create ──────────────────────────────────────────────────────
    createPreProcess(model: Y0Model, _files: FileObject[] | null): Promise<Y0Model> {
        return Promise.resolve(this.transformModel(model));
    }

    transformModel(model: Y0Model): Y0Model { return model; }

    protected async findEntity(id: number): Promise<Y0Entity> {
        let entity = null;
        if (id) {
            entity = await this.entity.findOneBy({ id, is_delete: 0 });
            if (entity == null) return Promise.reject('E10075');
        }
        return entity;
    }

    protected async saveData(model: Y0Model, _existEntity: Y0Entity): Promise<Y0Model> {
        model.id !== undefined ? (model.id = +model.id) : model;
        return this.entity.save({ ...model });
    }

    protected async filterFileData(files: FileObject[] | null, fileFieldName: string): Promise<any> {
        return files ? files.filter((file) => file.fieldname === fileFieldName) : null;
    }

    protected async uploadFiles(files: FileObject[] | null, modelName: string | null, fileFieldName: string, id): Promise<any> {
        if (files) {
            const fileObj = await this.filterFileData(files, fileFieldName);
            if (fileObj !== null && fileObj.length > 0) {
                return this.awsService.upload(fileObj, modelName, id);
            }
        }
        return null;
    }

    protected async transformFileData(model: Y0Model, files: FileObject[] | null): Promise<any> {
        return { ...model, files };
    }

    protected async updateFileData(awsRes: any, recordItem: Y0Model): Promise<Y0Model> {
        if (awsRes !== null) {
            recordItem = await this.transformFileData(recordItem, awsRes);
            const record = this.entity.create({ ...recordItem });
            recordItem = await record.save();                               // ⚠ B-11 second write
        }
        return recordItem;
    }

    createPostProcess(result: Y0Model, _model: Y0Model, _files: any): Promise<Y0Model> {
        return Promise.resolve(result);
    }

    public async createRecord(model: Y0Model, files: FileObject[] | null): Promise<Y0Model> {   // ⚠ B-11 no transaction
        model = await this.createPreProcess(model, files);
        const existEntity = await this.findEntity(model.id);
        const recordItem = await this.saveData(model, existEntity);
        const meta = this.getMetaModel();
        const awsRes = await this.uploadFiles(files, meta?.modelName, meta?.fileFieldName, recordItem.id);
        const final = await this.updateFileData(awsRes, recordItem);
        return this.createPostProcess(final, model, files);
    }

    MultiPreProcess(model: Y0Model | Y0Model[], _files: FileObject[] | null): Promise<Y0Model | Y0Model[]> {
        return Promise.resolve(model);
    }

    MultiPostProcess(result: Y0Model, _model: any, _files: FileObject[] | null): Promise<Y0Model> {
        return Promise.resolve(result);
    }

    public async createMultiRecords(models: Y0Model | Y0Model[], files: FileObject[] | null): Promise<any> {   // ⚠ B-11
        const modelsArray: any = await this.MultiPreProcess(models, files);
        const result = [];
        for (const model of modelsArray) {
            const record = await this.createPreProcess(model, files);
            const existEntity = await this.findEntity(record.id);
            const recordItem = await this.saveData(record, existEntity);
            const meta = this.getMetaModel();
            const res = await this.uploadFiles(files, meta?.modelName, meta?.fileFieldName, recordItem.id);
            const awsres = await this.updateFileData(res, recordItem);
            result.push(await this.MultiPostProcess(awsres, model, files));
        }
        return result;
    }

    // ── hard delete ─────────────────────────────────────────────────
    deletePreProcess(model: Y0Model): Promise<Y0Model> { return Promise.resolve(model); }
    deletePostProcess(result: Y0Model): Promise<Y0Model> { return Promise.resolve(result); }

    protected getFilePathData(model: Y0Model): Promise<any> {
        const metaModel = this.getMetaModel();
        const keys = metaModel.files.length !== 0 && metaModel !== null       // ⚠ B-01 null deref
            ? metaModel.files.map((file) => file.fileKey) : [];
        const deletePaths = [];
        for (const key of keys) if (model[key] !== undefined) deletePaths.push(model[key]);
        return Promise.resolve(deletePaths);
    }

    getDeleteEntity(): Y0Entity { return this.entity; }

    protected async deleteFileData(record, param, deletePaths): Promise<boolean> {
        if (!record) return false;
        if (deletePaths.length !== 0) await this.awsService.deleteFiles(deletePaths);
        await this.getDeleteEntity().remove(param.id);                         // ⚠ B-02 remove(id)
        return true;
    }

    public deleteData = async (param: any): Promise<any> => {
        const record = await this.findEntity(param.id);
        const preDeleteData = await this.deletePreProcess(record);
        const deletePaths = await this.getFilePathData(preDeleteData);
        await this.deleteFileData(preDeleteData, param, deletePaths);
        return this.deletePostProcess(preDeleteData);                          // ⚠ B-02 returns record, controller expects true
    };

    // ── soft delete ─────────────────────────────────────────────────
    updateDeleteFlagPreProcess(param: Y0Params): Promise<any> {
        return Promise.resolve(param.id ? In(Array.isArray(param.id) ? param.id : [param.id]) : null);
    }

    public updateDeleteFlagData = async (param: Y0Params): Promise<boolean> => {
        const whereid = await this.updateDeleteFlagPreProcess(param);
        if (whereid === null) return false;
        const record = await this.entity.find({ where: { id: whereid, is_delete: 0 } });   // ⚠ B-13 extra query
        if (record && record.length) {
            await this.entity.createQueryBuilder().update(this.entity).set({ is_delete: 1 }).where({ id: whereid }).execute();
            return true;
        }
        return false;
    };

    // ── files ───────────────────────────────────────────────────────
    public generateSignedUrl = async (folder: string, id: number, filename: string) => {
        if (filename != null) {
            return this.awsService.generateSignedUrl(`${AWS_S3_FOLDER_NAME}/${folder}/${id}/${filename}`);
        }
        return null;
    };

    // ── custom list (override prepareQuery) ────────────────────────
    async prepareQuery(param: Pagination): Promise<any> { return param; }
    postProcessAfterGetAll(result: Y0Model): Promise<Y0Model> { return Promise.resolve(result); }

    public getData = async (param: Pagination): Promise<any> => {
        const { records, totalRecords } = await this.prepareQuery(param);
        if (records && records.length > 0) {
            return { records: await this.postProcessAfterGetAll(records), totalRecords };
        }
        return { records, totalRecords };
    };

    // ── custom get-by-id ───────────────────────────────────────────
    async prepareQueryById(param: Y0Model): Promise<any> {
        if (param.id === undefined || param.id === null || typeof param.id !== 'number') {
            return Promise.reject('E10073');
        }
        return this.entity.findOneBy({ id: param.id, is_delete: 0 });
    }

    postProcessGetById(result: Y0Model): Promise<Y0Model> { return Promise.resolve(result); }

    public getDataById = async (param: Pagination): Promise<any> => {
        const record = await this.prepareQueryById(param);
        return this.postProcessGetById(record);
    };
}
```

> The repo version uses `new Promise(...)` wrappers and `.then()` chains; the above is behaviour-equivalent `async/await`
> (same hooks, same order, same rejections) and is easier to read. Swap back if you need byte-identical code.

### 5.22 Sample module — Health check (no DB)

```ts
// src/databases/repository/apiHealth/apiHealth.model.ts
import { Y0Model } from '../y0Model/y0Model.model';
export class APIHealthCheckModel extends Y0Model {}

// src/databases/repository/apiHealth/apiHealth.dto.ts
export class APIHealthCheckDto {}
```

```ts
// src/services/apiHealthService/apiHealthService.service.ts
import { AwsService } from '../../core/AwsService';
import { APIHealthCheckDto } from '../../databases/repository/apiHealth/apiHealth.dto';
import { APIHealthCheckModel } from '../../databases/repository/apiHealth/apiHealth.model';
import { Y0Entity } from '../../entities/y0Entity';
import { BaseServices } from '../baseService';

class APIHealthCheckService extends BaseServices {
    constructor(entity: any = Y0Entity, protected awsService: AwsService = new AwsService()) {
        super(entity, awsService);
    }
    getModel(): APIHealthCheckModel { return new APIHealthCheckModel(); }
    getDTO() { return APIHealthCheckDto; }

    public async apiHealthCheck(): Promise<string> {
        return 'API Server is up and running successfully!';
    }
}
export default APIHealthCheckService;
```

```ts
// src/controllers/apiHealthController/apiHealthController.controller.ts
import express from 'express';
import { APP_ROUTES } from '../../core/AppRoutes';
import { ResponseStatus, StatusCode } from '../../config';
import { BaseController } from '../baseController';
import APIHealthCheckService from '../../services/apiHealthService/apiHealthService.service';

export class APIHealthCheckController extends BaseController {
    constructor(path: APP_ROUTES.APIHEALTHCHECK, public router = express.Router(),
                public service: APIHealthCheckService = new APIHealthCheckService()) {
        super(path, router, service);
    }

    // Override: expose only the health route instead of the CRUD set
    public _initialiseRoutes(): void {
        this.router.get(`${this.path}/apihealth`, this.APIHealthCheck.bind(this));
    }

    public APIHealthCheck(_req: express.Request, res: express.Response) {
        this.service.apiHealthCheck()
            .then((data) => this.sendResponse(StatusCode.SUCCESS, 'API Server is up and running successfully!', data as any, 0, null, res, ResponseStatus.SUCCESS))
            .catch((error) => this.handleError(error, res));
    }
}
```

> The repo version also has `/workerhealth` and `/workerstatus`, which depend on the workflow engine (`engine/`, `queue/`) and are not part of the reusable template.

### 5.23 `src/swagger.ts` (skeleton)

```ts
import swaggerUi from 'swagger-ui-express';
import express from 'express';
import { PATH } from './config';

const swaggerSpec = {
    openapi: '3.0.0',
    info: { title: 'My Service API', version: '1.0.0' },
    servers: [{ url: `http://localhost:3000${PATH}`, description: 'Local' }],
    components: {
        securitySchemes: { BearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' } },
        schemas: {
            GenericResponse: {
                type: 'object',
                properties: {
                    status: { type: 'string', example: '10000' },
                    msg: { type: 'string' },
                    details: { type: 'object', nullable: true },
                    error: { type: 'string', nullable: true },
                    totalRecords: { type: 'number', example: 0 },
                },
            },
        },
    },
    paths: { /* add per module */ },
};

export function setupSwagger(app: express.Application): void {
    app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec, { explorer: true }));
    app.get('/api-docs.json', (_req, res) => res.json(swaggerSpec));
}
```

### 5.24 Dockerfile

```dockerfile
# ---------- Stage 1: build ----------
FROM node:22.17.0-alpine3.22 AS builder
WORKDIR /app
RUN apk add --no-cache python3 make g++          # only if native addons are used
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src/ ./src/
RUN npm run build && npm prune --omit=dev

# ---------- Stage 2: runtime ----------
FROM node:22.17.0-alpine3.22
WORKDIR /app
ENV NODE_ENV=production
COPY --from=builder /app/build ./build
COPY --from=builder /app/package.json ./
COPY --from=builder /app/node_modules ./node_modules
USER node
EXPOSE 3000
CMD ["node", "build/index.js"]
```

> Differences vs. the repo Dockerfile are explained in B-22.

---

## 6. Adding a New Module — Step by Step

Example: **Product** with an optional image upload.

**1. Entity** — `src/entities/productEntity.ts`

```ts
import { Column, Entity } from 'typeorm';
import { Y0Entity } from './y0Entity';

@Entity('product_tbl')
export class ProductEntity extends Y0Entity {
    @Column({ type: 'varchar', length: 200 }) name: string;
    @Column({ type: 'numeric', nullable: true }) price: number;
    @Column({ type: 'varchar', nullable: true }) image: string;
}
```

Register it in `dataSource.ts → entities: [ProductEntity]`.

**2. Model** — `src/databases/repository/product/product.model.ts` (field whitelist; *initialise every field*)

```ts
import { Y0Model } from '../y0Model/y0Model.model';
export class ProductModel extends Y0Model {
    name: string = null;
    price: number = null;
    image: string = null;
}
```

**3. DTO** — `src/databases/repository/product/product.dto.ts`

```ts
import { IsNotEmpty, IsNumber, IsOptional, Validate } from 'class-validator';
import { FileExistsValidator } from '../../../core/FileExistValidatorfn';

export class ProductDto {
    @IsNotEmpty() name: string;
    @IsOptional() @IsNumber() price: number;
    @Validate(FileExistsValidator, { message: 'Invalid image (size/type)' }) files: any;
}
```

**4. Service** — `src/services/productService/productService.service.ts`

```ts
import { AwsService } from '../../core/AwsService';
import { MetaModel } from '../../core/MetaModel';
import { ProductEntity } from '../../entities/productEntity';
import { ProductModel } from '../../databases/repository/product/product.model';
import { ProductDto } from '../../databases/repository/product/product.dto';
import { BaseServices } from '../baseService';

export default class ProductService extends BaseServices {
    constructor(entity: any = ProductEntity, protected awsService: AwsService = new AwsService()) {
        super(entity, awsService);
    }
    getModel() { return new ProductModel(); }
    getDTO() { return ProductDto; }
    getModuleName() { return 'Product'; }
    getGolbalSearchColumns() { return ['main.name']; }
    getMetaModel() {
        return new MetaModel('product', 'image', [
            { fileKey: 'image', allowedSize: 5 * 1024 * 1024, allowedExtensions: ['image/png', 'image/jpeg'], colName: 'image', require: 'false' },
        ]);
    }
}
```

**5. Controller** — `src/controllers/productController/productController.controller.ts`

```ts
import express from 'express';
import { APP_ROUTES } from '../../core/AppRoutes';
import { BaseController } from '../baseController';
import ProductService from '../../services/productService/productService.service';

export class ProductController extends BaseController {
    constructor(path: APP_ROUTES.PRODUCT, public router = express.Router(), public service: ProductService = new ProductService()) {
        super(path, router, service);
    }
    // Optional: override _initialiseRoutes() to add/remove routes (call super._initialiseRoutes() to keep CRUD).
}
```

**6. Route + registration** — add `PRODUCT = '/product'` to `APP_ROUTES`; add `new ProductController(APP_ROUTES.PRODUCT)` in `index.ts`.

**7. Test** — `src/controllers/productController/__tests__/product.routes.test.ts` with `vitest` + `supertest`, mocking the service and `auth.middleware` (see the existing `apiHealthController.workerStatus.test.ts` for the pattern: `vi.hoisted` + `vi.mock`).

---

## 7. Auto-generated CRUD Endpoints

Every controller that keeps the default `_initialiseRoutes()` gets (all behind `authMiddleware`):

| Method | Path (`PATH` + module prefix +) | Body / Params | Service method |
|---|---|---|---|
| POST | `/getall` | `{ pageNumber, pageSize, search }` | `getAll` |
| GET | `/getbyid/:id` | `:id` | `getById` |
| POST | `/save` | form-data/JSON matching Model (+ files); `id` present ⇒ update | `createRecord` |
| POST | `/savemulti` | array of Models | `createMultiRecords` |
| DELETE | `/delete/:id` | `:id` (hard delete + S3 files) | `deleteData` |
| POST | `/updateDeleteFlagData` | `{ id: number \| number[] }` (soft delete) | `updateDeleteFlagData` |
| POST | `/getdata` | any (custom) | `getData` → `prepareQuery` |
| POST | `/getdatabyid` | `{ id }` | `getDataById` → `prepareQueryById` |

---

## 8. Response Contract & Error Codes

**Controller responses (`GenericResponse`):**

```json
{
  "status": "10000",
  "msg": "Product Fetched Successfully",
  "error": null,
  "details": [ ... ],
  "totalRecords": 42
}
```

`status`: `10000` success, `10001` failure, `10003` invalid access token, `10004` invalid encrypted input.
HTTP status comes from `ErrorCodes[code].status` on failure.

**Middleware / framework responses (`ApiResponse` subclasses):** `{ "statusCode": "10001", "message": "..." }` (+ `url` for 404/405).

**Error flow:** service `reject('E10075')` or `reject({ code: 'E30001', message?, meta? })` → `BaseController.handleError` → `ErrorCodes` lookup (unknown → `E10005`, 500).

---

## 9. Bottlenecks & Issues in the Current Code

Severity: 🔴 Critical (breaks build/runtime or data) · 🟠 High (performance/security under load) · 🟡 Medium · ⚪ Low (hygiene).

### 9.1 Build / startup blockers

| ID | Sev | Where | Problem | Fix |
|---|---|---|---|---|
| B-03 | 🔴 | [app.ts:5-24](src/app.ts#L5-L24), [dataSource.ts:2-16](src/databases/dataSource.ts#L2-L16), [auth.middleware.ts:3](src/middlewares/auth.middleware.ts#L3), [apiHealthService.service.ts:5-8](src/services/apiHealthService/apiHealthService.service.ts#L5-L8), [apiHealth.model.ts:1](src/databases/repository/apiHealth/apiHealth.model.ts#L1) | **~25 imports point to files that don't exist** in this template (`engine/`, `queue/`, `nodes/`, `utils/natsStream`, `utils/webSocketService`, `utils/schedulers`, `utils/deadline`, `controllers/abortController`, `controllers/fileAccess`, 14 entities incl. `userLoginsEntity`). `app.ts` also imports config names (`ABORT_WORKFLOW`, `NATS_*`, `DRAIN_BUDGET_MS`, `FILE_SERVE_ROUTE`, `WORKFLOW_DRAIN_ENABLED`) that `config.ts` doesn't export. The project **does not compile**. | Use the trimmed files in Section 5; ship a `UserLoginsEntity` (or swap auth to stateless JWT). |
| B-05 | 🔴 | [config.ts:34](src/config.ts#L34) | `WEBHOOK_URL` uses `API_DOMAIN`, which is never declared → compile error / `ReferenceError` on import. | Remove, or add `export const API_DOMAIN = process.env.API_DOMAIN!` above it. |
| B-04 | 🔴 | [dataSource.ts:40](src/databases/dataSource.ts#L40) | `entities: []` — entity imports exist but none are registered, so every `Entity.find/save` throws *"No metadata for entity"*. | List every entity, or use a glob: `entities: [__dirname + '/../entities/*.{ts,js}']`. |
| B-24 | 🔴 | [tsconfig.json](tsconfig.json), [index.ts](src/index.ts) | `reflect-metadata` is a dependency but never imported, and `emitDecoratorMetadata` is off. TypeORM / class-transformer decorators rely on both. Also `strict: true` is neutralised by `noImplicitAny:false` + `strictNullChecks:false`, and `lib: ES6` mismatches `target: es2020`. | `import 'reflect-metadata'` first line of `index.ts`; enable `emitDecoratorMetadata`; set `lib: ["ES2021"]`; turn on `strictNullChecks` gradually. |
| B-06 | 🔴 | [app.ts:34](src/app.ts#L34), [app.ts:113-127](src/app.ts#L113-L127) | `bootstrap()` (DB connect) is async but called from the constructor without `await`; `listen()` starts accepting traffic **before** the DB is connected → early requests fail (`entityManager` null / no connection). | Make startup explicit: `await app.init(); app.listen();` in `index.ts`. Also add `SIGTERM` handler to close server + `dataSource.destroy()`. |

### 9.2 Correctness bugs in base classes

| ID | Sev | Where | Problem | Fix |
|---|---|---|---|---|
| B-01 | 🔴 | [baseService.ts:285](src/services/baseService.ts#L285) | `metaModel.files.length !== 0 && metaModel !== null` dereferences before the null check. Default `getMetaModel()` returns `null` ⇒ **`DELETE /delete/:id` crashes for every module without files**. | `const keys = metaModel?.files?.map(f => f.fileKey) ?? [];` |
| B-02 | 🔴 | [baseService.ts:304-332](src/services/baseService.ts#L304-L332), [baseController.ts:140](src/controllers/baseController.ts#L140) | `entity.remove(param.id)` — `BaseEntity.remove` takes an entity, not an id. `deleteData` returns the record, but the controller checks `response == true` ⇒ always reports error even on success. Also hard delete conflicts with the `is_delete` soft-delete convention. | Use `this.entity.delete({ id })`; return `true`; consider making delete soft by default. |
| B-11 | 🟠 | [baseService.ts:202-266](src/services/baseService.ts#L202-L266) | `createRecord` = SELECT + INSERT + S3 upload + second INSERT/UPDATE, **no transaction**: if S3 fails the row stays without file; if the second save fails the file is orphaned in S3. `createMultiRecords` loops sequentially (4N round-trips) and a failure in item k leaves k-1 items committed. `existEntity` is fetched but never used. | Wrap in `Database.executeInTransaction`; upload to S3 first (or use outbox/cleanup), single save; batch insert for multi; skip `findEntity` when `id` is absent. |
| B-12 | 🟠 | [validationFormData.middleware.ts:13](src/middlewares/validationFormData.middleware.ts#L13), [:20](src/middlewares/validationFormData.middleware.ts#L20), [:53](src/middlewares/validationFormData.middleware.ts#L53) | `type.files = validFiles` writes onto the **shared DTO class** → state leaks between concurrent requests. `error.constraints` is undefined for nested errors → `Object.values(undefined)` throws (unhandled promise, request hangs). Logs whole file buffers to console. No `.catch` on `validate()`. | Remove the static assignment; use `error.constraints ?? {}`; add `.catch(next)`; drop the `console.log`. Consider `whitelist: true, forbidNonWhitelisted: true`. |
| B-15 | 🟡 | [baseController.ts:67-96](src/controllers/baseController.ts#L67-L96) | `+req.params.id` gives `NaN` for non-numeric ids; `validateData` only checks `=== null`, so `NaN` reaches the DB. Invalid id produces 500 (`E10005`) instead of 400. | `Number.isInteger(id) && id > 0`, else `handleError('E10073')`. |
| B-14 | 🟡 | [app.ts:100-111](src/app.ts#L100-L111) | 405 detection compares literal paths, so parameterised routes (`/getbyid/:id`) always fall to 404; only `route.stack[0].method` is recorded. **No 4-arg Express error handler** → thrown errors / JSON parse errors return Express's default HTML page. | Add `app.use((err, req, res, next) => ApiError.handle(...))`; match paths with `path-to-regexp` or drop custom 405. |
| B-16 | 🟡 | [baseController.ts:229](src/controllers/baseController.ts#L229), [ApiResponse.ts:25](src/core/ApiResponse.ts#L25), [app.ts:63](src/app.ts#L63) | Encryption bypass lists are inconsistent: app-level check uses full `PATH` URLs, controller/response use bare `/security/...` while `res.req.url` inside a router is mount-relative. Three copies of the same list (`NON_ENCRYPTION_ENDPOINTS`, `NonTokenApiEndpoints`, hard-coded strings). | One helper `isEncryptionExempt(req)` using `req.originalUrl` + the single config list. |
| B-27 | ⚪ | [ApiError.ts:56](src/core/ApiError.ts#L56) | `error.detail.split('Key')[1].split(...)` throws if `detail` is missing/different format → error handler itself crashes. | Guard with optional chaining and a fallback message. |
| B-20 | 🟡 | [AwsService.ts:29-31](src/core/AwsService.ts#L29-L31), [:42-44](src/core/AwsService.ts#L42-L44), [:103-105](src/core/AwsService.ts#L103-L105) | Errors are **returned instead of thrown** (`return e`, `return error`, `return undefined`) → callers treat failed uploads/deletes as success and store the error object as file data. | Throw; let the service decide. |

### 9.3 Performance / scalability bottlenecks

| ID | Sev | Where | Problem | Fix |
|---|---|---|---|---|
| B-07 | 🟠 | [app.ts:49-55](src/app.ts#L49-L55) | `multer().any()` is **global** with memory storage and a 250 MB limit: every route accepts files and buffers them fully in RAM, no file-count limit. A handful of parallel uploads can OOM the pod; also wasted parsing on non-upload routes. `express.json` limit 15 MB on every route. | Apply multer per route (only `/save`, `/savemulti`), set `files`/`fieldSize` limits, use streaming to S3 (`multer-s3` is already a dep) or disk storage; lower JSON limit (e.g. 1 MB) and raise per-route where needed. |
| B-08 | 🟠 | [auth.middleware.ts:13-28](src/middlewares/auth.middleware.ts#L13-L28), [jwt.ts:9](src/utils/jwt/jwt.ts#L9) | Every authenticated request does a DB lookup on `user_logins` (by `userid` + full token string — needs a composite index). Token is verified with `ignoreExpiration: true` and expiry is checked **after** the DB call, so expired tokens still cost a query. Access and refresh tokens share one secret and are indistinguishable. | Check `exp` first (drop `ignoreExpiration`); cache valid sessions in Redis/LRU with TTL = token TTL; store a token hash/`jti` instead of the whole token; separate refresh secret + `type` claim. |
| B-09 | 🟠 | [baseService.ts:39-46](src/services/baseService.ts#L39-L46), [baseController.ts:45-50](src/controllers/baseController.ts#L45-L50) | `pageNumber` defaults to **0 ⇒ no LIMIT ⇒ full table returned**. `pageSize` comes straight from the client with no cap. `getManyAndCount` runs a COUNT on every page. | Default `pageNumber=1`, clamp `pageSize` (e.g. ≤ 100); allow skipping count; keyset pagination for large tables. |
| B-10 | 🟡 | [baseService.ts:51-67](src/services/baseService.ts#L51-L67) | Global search uses `LOWER(col) LIKE '%x%'` across N columns with OR → can't use B-tree indexes, full scans. | Postgres `ILIKE` + `pg_trgm` GIN indexes, or full-text search (`tsvector`). Also index `(is_delete, created_at)` for the default filter/order. |
| B-13 | ⚪ | [baseService.ts:346-363](src/services/baseService.ts#L346-L363) | Soft delete does a `find` and then an `update` (2 queries); `record != ''` comparison is fragile. | Single `UPDATE ... WHERE id IN (...) AND is_delete = 0` and check `affected`. |
| B-17 | 🟡 | [AwsService.ts:10-19](src/core/AwsService.ts#L10-L19), each service constructor | Every service instance does `new AwsService()` → a new S3 client (and HTTP agent) per module. `aws-sdk` v2 is end-of-support. `getMedia`/`deleteFiles` loop sequentially and buffer full objects. | Singleton S3 client; migrate to `@aws-sdk/client-s3` v3; use `DeleteObjects` batch; stream instead of buffer. |
| B-18 | 🟡 | [EmailService.ts:17](src/utils/email/EmailService.ts#L17) | A new nodemailer transporter (with `pool: true`) is created **per email** → the pool is never reused, new SMTP/TLS handshake every send. | Create the transporter once (module-level) and reuse; queue bulk email. |
| B-23 | 🟡 | Everywhere (`console.log('------------url-----------')`, etc.) | Synchronous `console.*` on every request in the hot path; no request id, no levels, file buffers logged. `QueryLogger` exists but isn't wired. | Structured async logger (pino) + request-id middleware; enable `QueryLogger` only in dev. |

### 9.4 Security

| ID | Sev | Where | Problem | Fix |
|---|---|---|---|---|
| B-19 | 🟠 | [dataSource.ts:43-46](src/databases/dataSource.ts#L43-L46), [EmailService.ts:22-24](src/utils/email/EmailService.ts#L22-L24) | TLS certificate validation disabled (`rejectUnauthorized: false`) for both Postgres and SMTP → MITM possible. | Provide the CA bundle (e.g. AWS RDS CA) and enable validation. |
| B-25 | 🟠 | [package.json](package.json) | Dependency bloat (~60 deps) for a template: `vm2` (deprecated, known sandbox-escape CVEs), `xlsx@0.18.5` (known prototype-pollution/ReDoS, no npm fix), `aws-sdk` v2 (EOS), 4 AI SDKs, 5 DB drivers (`mongodb`, `mysql2`, `sqlite3`, `tedious`, `pg`), `isolated-vm`, `moment`, `json2csv@alpha`. Larger attack surface, slower installs, native builds in Docker. | Keep only the list in 5.1; add others per project. Run `npm audit` in CI. |
| B-26 | 🟡 | [config.ts](src/config.ts) | Env vars are read with `!` but never validated → a missing `JWT_SECRET_KEY` silently becomes `undefined` and fails at request time. `cors()` allows every origin. | Validate env at startup (zod/envalid) and fail fast; configure CORS origins per environment; add rate limiting on auth routes. |

### 9.5 Tooling / DevOps

| ID | Sev | Where | Problem | Fix |
|---|---|---|---|---|
| B-21 | 🟡 | [package.json](package.json) scripts | `set NODE_ENV=x&& ...` only works on Windows `cmd`; breaks on Linux/macOS/CI. `lint` script exists but `eslint` isn't installed and there is no config. No vitest config. | `cross-env`; add `eslint` + `@typescript-eslint` config; add `vitest.config.ts`. |
| B-22 | 🟡 | [Dockerfile_Dev_Workflow_Service](Dockerfile_Dev_Workflow_Service), [.gitignore](.gitignore) | `package-lock.json` is **git-ignored** and the image uses `npm install --legacy-peer-deps` → non-reproducible builds. Dev deps shipped to runtime image. `NODE_ENV=development` baked into runtime. Runs as root. `pm2-runtime -i 1` inside a container adds a process manager with no benefit (orchestrator already restarts). No `HEALTHCHECK`/graceful shutdown. | Commit the lockfile, `npm ci`, `npm prune --omit=dev`, `USER node`, `node build/index.js`, env per deployment (see 5.24). |
| B-28 | ⚪ | [README.md](README.md) | Empty README; `swagger.ts` hard-codes product name, domains and port `3222`; `Y0Params.ts`, `AppRoutes.ts`, `emailTemplates.ts` (643 lines) contain workflow-project-specific content. | Keep project-specific items out of the template; parameterise swagger servers from config. |
| B-29 | ⚪ | Naming | Typos and inconsistencies propagate into every project: `getGolbalSearchColumns`, `WorflowDatabase`, `creadentialManagement`, `feilds`, `responce`, `MultiPreProcess` (PascalCase method), `Encryption&Decryption.ts` (`&` in filename is shell-hostile), duplicate `sanitizeFile` implementations with different return shapes, `index.ts` calling `dotenv.config()` after `config.ts` has already loaded env. | Fix once in the template before copying (rename + find/replace). |

### 9.6 Priority order for fixing

1. **B-03, B-05, B-04, B-24, B-06** — make it compile and start safely.
2. **B-01, B-02, B-12** — base-class bugs that every module inherits.
3. **B-07, B-08, B-09** — biggest runtime load / memory risks.
4. **B-11, B-20, B-14** — data consistency and error handling.
5. **B-19, B-25, B-26** — security hardening.
6. Rest — tooling and hygiene.

---

## 10. New-Project Bootstrap Checklist

- [ ] Copy `src/` base files from Section 5 (controllers/baseController, services/baseService, core/*, middlewares/*, databases/*, entities/y0Entity, utils/jwt, utils/email).
- [ ] Rename `PATH`, port env var, swagger title/servers, Docker workdir, package name.
- [ ] Create `.env.dev` (and uat/beta/prod) with the keys listed in 5.4.
- [ ] Add `UserLoginsEntity` (or adapt `auth.middleware.ts`) and register all entities in `dataSource.ts`.
- [ ] `import 'reflect-metadata'` at the top of `index.ts`; enable `emitDecoratorMetadata`.
- [ ] Apply at least the 🔴 fixes from Section 9.
- [ ] Commit `package-lock.json`; use `cross-env` in scripts.
- [ ] Add modules using Section 6; add each to `APP_ROUTES` + `index.ts`.
- [ ] Add tests next to each controller/service in `__tests__/`.
- [ ] Verify: `npm run build`, `npm test`, `GET {PATH}/apiHealthCheck/apihealth` returns `status: "10000"`.
