using System.Collections;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Diagnostics;
using System.Security.Cryptography;
using UnityEngine;
using Mirror;
using UnityEngine.SceneManagement;

public class ControlsV2 : NetworkBehaviour
{
    public NetworkManager manager;
    public float walkSpeed = 1f;
    public float maxWalkSpeed = 1f;
    public float sprintSpeed = 1f;
    public float maxSprintSpeed = 1f;
    public float jumpHeight = 1f;
    public float mouseSpeed = 1f;

    float speed = 1f;
    float maxSpeed = 1f;

    Rigidbody player;
    GameObject head;

    void Start()
    {
        Cursor.visible = false;
        Cursor.lockState = CursorLockMode.Locked;
        player = GetComponent<Rigidbody>();
        head = GameObject.Find("Head");
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


        if (Input.GetKey("left shift")){
            speed = sprintSpeed;
            maxSpeed = maxSprintSpeed;
        }
        else
        {
            speed = walkSpeed;
            maxSpeed = maxWalkSpeed;

        }
        
        if (Input.GetKey(KeyCode.F))
        {

            transform.rotation = Quaternion.Euler(0, 0, 0);
            player.velocity = new Vector3(0, 0, 0);
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

        player.transform.Rotate(0, Input.GetAxis("Mouse X")*mouseSpeed, 0, Space.Self);

        head.transform.Rotate(Input.GetAxis("Mouse Y") * -mouseSpeed, 0, 0, Space.Self);

    }

    void OnCollisionStay(Collision collision)
    {
        if ((collision.gameObject.tag == "Floor") && (Input.GetKey("space")))
        {
            
            player.AddForce(transform.up * jumpHeight);
        }
    }
}

