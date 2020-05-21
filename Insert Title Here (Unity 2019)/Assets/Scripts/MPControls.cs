﻿using System.Collections;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Diagnostics;
using System.Security.Cryptography;
using UnityEngine.SceneManagement;
using UnityEngine;
using UnityEngine.UI;
using Mirror;

public class MPControls : NetworkBehaviour
{
    
    public float walkSpeed = 1f;
    public float maxWalkSpeed = 1f;
    public float sprintSpeed = 1f;
    public float maxSprintSpeed = 1f;
    public float jumpHeight = 1f;

    float speed = 1f;
    float maxSpeed = 1f;

    Rigidbody player;
    NetworkManager manager;

    void Start()
    {
        Cursor.visible = false;
        Cursor.lockState = CursorLockMode.Locked;
        player = GetComponent<Rigidbody>();

        manager = GetComponent<NetworkManager>();
        
    }

    void Update()
    {

        if (!isLocalPlayer)
        {
            return;
        }

        if (Input.GetKey(KeyCode.P))
        {
            Cursor.visible = true;
            Cursor.lockState = CursorLockMode.None;
            SceneManager.LoadScene("Menu");
        }


        if (Input.GetKey("left shift"))
        {
            speed = sprintSpeed;
            maxSpeed = maxSprintSpeed;
        }
        else
        {
            speed = walkSpeed;
            maxSpeed = maxWalkSpeed;

        }

        if (player.velocity.magnitude <= maxSpeed)
        {
            if (Input.GetKey(KeyCode.W))
            {
                player.AddForce(transform.forward * speed);
            }
            if (Input.GetKey(KeyCode.S))
            {
                player.AddForce(-transform.forward * speed);

            }
            if (Input.GetKey(KeyCode.A))
            {
                player.AddForce(-transform.right * speed);

            }
            if (Input.GetKey(KeyCode.D))
            {
                player.AddForce(transform.right * speed);

            }
        }



    }

    void OnCollisionStay(Collision collision)
    {
        if ((collision.gameObject.tag == "Floor") && (Input.GetKey("space")))
        {

            player.AddForce(transform.up * jumpHeight);
        }
    }
}

