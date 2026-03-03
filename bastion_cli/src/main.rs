mod cli;
mod handlers;
mod identity;
mod keys;
mod permissions;
mod requests;
mod session;

use clap::Parser;
use cli::{Cli, Commands};
use sqlx::PgPool;
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Handle raw command input from wrapper script (to avoid shell expansion issues)
    let args: Vec<String> = env::args().collect();
    let cli = if args.len() > 1 && args[1] == "--raw" {
        if args.len() < 3 {
            eprintln!("Error: --raw requires a command string");
            std::process::exit(1);
        }
        let raw_command = &args[2];
        let split_args = shell_words::split(raw_command)?;
        // Prepend the binary name (args[0]) to satisfy clap
        let mut new_args = vec![args[0].clone()];
        new_args.extend(split_args);
        Cli::parse_from(new_args)
    } else {
        Cli::parse()
    };

    // Establish a Database Connection Pool
    let database_url =
        env::var("DATABASE_URL").expect("DATABASE_URL environment variable must be set");
    let pool = PgPool::connect(&database_url).await?;
    println!("--> Successfully connected to the database.");

    // Identify the user securely
    // 1. Try to identify via SSH Key Fingerprint (strongest method)
    let fingerprint = identity::get_ssh_key_fingerprint();
    let mut actual_user = if let Some(ref fp) = fingerprint {
        println!("--> Debug: Lookup user by fingerprint: '{}'", fp);
        let u = identity::identify_user_by_key(&pool, fp).await?;
        if let Some(ref found) = u {
            println!("--> Debug: Found user '{}'", found);
        } else {
            println!("--> Debug: No user found for this fingerprint.");
        }
        u
    } else {
        println!("--> Debug: No fingerprint found in environment.");
        None
    };

    // 2. Fallback to OS user if no key match (weak/legacy method)
    // In our single-user docker setup, $USER is always 'dev', so checking the DB
    // for a key match is CRITICAL to distinguish 'intern' from 'dev'.
    let user =
        actual_user.unwrap_or_else(|| env::var("USER").unwrap_or_else(|_| "unknown".to_string()));

    match &cli.command {
        Commands::Ping => {
            println!("Pong!");
        }

        Commands::Connect { server_name } => {
            handlers::handle_connect(&pool, &user, server_name).await?;
        }

        Commands::List => {
            handlers::handle_list(&pool, &user).await?;
        }

        Commands::Request {
            server_name,
            hours,
            note,
        } => {
            handlers::handle_request(&pool, &user, server_name, *hours, note.as_deref()).await?;
        }

        Commands::Pending => {
            if !permissions::is_admin(&pool, &user).await? {
                eprintln!("--> Error: Only admins can view pending requests");
                return Ok(());
            }
            handlers::handle_pending(&pool).await?;
        }

        Commands::Approve { request_id, hours } => {
            if !permissions::is_admin(&pool, &user).await? {
                eprintln!("--> Error: Only admins can approve requests");
                return Ok(());
            }
            handlers::handle_approve(&pool, *request_id, &user, *hours).await?;
        }

        Commands::Deny { request_id, reason } => {
            if !permissions::is_admin(&pool, &user).await? {
                eprintln!("--> Error: Only admins can deny requests");
                return Ok(());
            }
            handlers::handle_deny(&pool, *request_id, &user, reason).await?;
        }

        Commands::MyRequests => {
            handlers::handle_my_requests(&pool, &user).await?;
        }

        Commands::ListAccess => {
            handlers::handle_list_access(&pool, &user).await?;
        }

        Commands::Grant {
            username,
            server_name,
            hours,
        } => {
            if !permissions::is_admin(&pool, &user).await? {
                eprintln!("--> Error: Only admins can grant direct access");
                return Ok(());
            }
            handlers::handle_grant(&pool, username, server_name, *hours, &user).await?;
        }

        Commands::AddKey {
            file,
            key_data,
            ttl,
            comment,
        } => {
            handlers::handle_add_key(
                &pool,
                &user,
                file.clone(),
                key_data.clone(),
                ttl.clone(),
                comment.clone(),
            )
            .await?;
        }

        Commands::ListKeys => {
            handlers::handle_list_keys(&pool, &user).await?;
        }

        Commands::RevokeKey { key_id } => {
            handlers::handle_revoke_key(&pool, &user, key_id).await?;
        }

        Commands::KeyInfo { key_id } => {
            handlers::handle_key_info(&pool, &user, key_id).await?;
        }

        Commands::MakeAdmin { username } => {
            if !permissions::is_admin(&pool, &user).await? {
                eprintln!("--> Error: Only admins can promote users to admin");
                return Ok(());
            }
            handlers::handle_make_admin(&pool, username).await?;
        }

        Commands::RevokeAdmin { username } => {
            if !permissions::is_admin(&pool, &user).await? {
                eprintln!("--> Error: Only admins can revoke admin privileges");
                return Ok(());
            }
            handlers::handle_revoke_admin(&pool, username).await?;
        }

        Commands::ListUsers => {
            if !permissions::is_admin(&pool, &user).await? {
                eprintln!("--> Error: Only admins can list all users");
                return Ok(());
            }
            handlers::handle_list_users(&pool).await?;
        }
    }

    Ok(())
}
