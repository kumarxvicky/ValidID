IF DB_ID(N'UserIdentification') IS NULL
BEGIN
  CREATE DATABASE [UserIdentification];
END;
GO

USE [UserIdentification];
GO

IF OBJECT_ID(N'dbo.users', N'U') IS NULL
BEGIN
  CREATE TABLE dbo.users (
    id BIGINT IDENTITY(1,1) NOT NULL,
    public_id UNIQUEIDENTIFIER NOT NULL CONSTRAINT DF_users_public_id DEFAULT NEWID(),
    full_name NVARCHAR(100) NOT NULL,
    email NVARCHAR(254) NOT NULL,
    password_hash NVARCHAR(255) NOT NULL,
    role NVARCHAR(20) NOT NULL CONSTRAINT DF_users_role DEFAULT 'user',
    is_active BIT NOT NULL CONSTRAINT DF_users_is_active DEFAULT 1,
    created_at DATETIME2(3) NOT NULL CONSTRAINT DF_users_created_at DEFAULT SYSUTCDATETIME(),
    updated_at DATETIME2(3) NOT NULL CONSTRAINT DF_users_updated_at DEFAULT SYSUTCDATETIME(),
    CONSTRAINT PK_users PRIMARY KEY (id),
    CONSTRAINT UQ_users_public_id UNIQUE (public_id),
    CONSTRAINT UQ_users_email UNIQUE (email),
    CONSTRAINT CK_users_role CHECK (role IN ('user', 'admin'))
  );
END;
ELSE
BEGIN
  IF COL_LENGTH(N'dbo.users', N'role') IS NULL
  BEGIN
    ALTER TABLE dbo.users
      ADD role NVARCHAR(20) NOT NULL
      CONSTRAINT DF_users_role DEFAULT 'user';
  END;

  IF COL_LENGTH(N'dbo.users', N'is_active') IS NULL
  BEGIN
    ALTER TABLE dbo.users
      ADD is_active BIT NOT NULL
      CONSTRAINT DF_users_is_active DEFAULT 1;
  END;
END;
GO

IF OBJECT_ID(N'dbo.sessions', N'U') IS NULL
BEGIN
  CREATE TABLE dbo.sessions (
    session_id NVARCHAR(128) COLLATE Latin1_General_100_BIN2 NOT NULL,
    expires_at DATETIME2(3) NOT NULL,
    session_data NVARCHAR(MAX) NOT NULL,
    CONSTRAINT PK_sessions PRIMARY KEY (session_id)
  );

  CREATE INDEX IX_sessions_expires_at ON dbo.sessions (expires_at);
END;
GO

