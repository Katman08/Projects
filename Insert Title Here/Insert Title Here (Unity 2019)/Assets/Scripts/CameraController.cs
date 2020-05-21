using System.Collections;
using System.Collections.Generic;
using UnityEngine;

public class CameraController : MonoBehaviour
{

    public float mouseSpeed = 1f;

    Rigidbody player;
    GameObject head;

    // Start is called before the first frame update
    void Start()
    {
        player = transform.root.gameObject.GetComponent<Rigidbody>();
        head = transform.parent.gameObject;
    }

    // Update is called once per frame
    void Update()
    {
        player.transform.Rotate(0, Input.GetAxis("Mouse X") * mouseSpeed, 0, Space.Self);
        head.transform.Rotate(Input.GetAxis("Mouse Y") * -mouseSpeed, 0, 0, Space.Self);

    }
}
